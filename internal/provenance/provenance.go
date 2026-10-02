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

	slsa "github.com/in-toto/attestation/go/predicates/provenance/v1"
	intoto "github.com/in-toto/attestation/go/v1"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/alejandro-velasco/bomify/internal/buildinfo"
	"github.com/alejandro-velasco/bomify/internal/fsutil"
	"github.com/alejandro-velasco/bomify/internal/layout"
	pluginlib "github.com/alejandro-velasco/bomify/pkg/plugin"
)

const (
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
	// InvocationIDEnv names the environment variable a CI pipeline sets to
	// identify its run (e.g. the job's URL) as runDetails.metadata's
	// invocationId.
	InvocationIDEnv = "BOMIFY_INVOCATION_ID"
)

// Recorder collects a build's resolved dependencies as its components are
// pulled. It's safe for concurrent use.
type Recorder struct {
	started time.Time

	mu      sync.Mutex
	deps    map[string]*intoto.ResourceDescriptor
	plugins map[string]bool
}

// NewRecorder starts recording a build now.
func NewRecorder() *Recorder {
	return &Recorder{started: time.Now(), deps: map[string]*intoto.ResourceDescriptor{}, plugins: map[string]bool{}}
}

// AddComponent records a pulled component by purl and, if known, the
// SHA-256 of what was pulled.
func (r *Recorder) AddComponent(purl, sha256 string) {
	r.add(&intoto.ResourceDescriptor{Uri: purl, Digest: digest(sha256)})
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
	r.add(&intoto.ResourceDescriptor{Uri: uri, Name: "bomify-plugin-" + kind, Digest: digest(sum)})
	return nil
}

func (r *Recorder) add(d *intoto.ResourceDescriptor) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.deps[d.GetUri()] = d
}

// Write records the build of the SBOM hashing to sbomHash, tagged tags, as
// baseDir's provenance for that build, replacing any earlier record.
func (r *Recorder) Write(baseDir, sbomHash string, tags []string) error {
	r.mu.Lock()
	deps := make([]*intoto.ResourceDescriptor, 0, len(r.deps))
	for _, d := range r.deps {
		deps = append(deps, d)
	}
	r.mu.Unlock()
	slices.SortFunc(deps, func(a, b *intoto.ResourceDescriptor) int { return strings.Compare(a.GetUri(), b.GetUri()) })

	params, err := externalParameters(sbomHash, tags)
	if err != nil {
		return err
	}
	p := &slsa.Provenance{
		BuildDefinition: &slsa.BuildDefinition{
			BuildType:            BuildType,
			ExternalParameters:   params,
			ResolvedDependencies: deps,
		},
		RunDetails: &slsa.RunDetails{
			Builder: &slsa.Builder{Id: BuilderID, Version: map[string]string{"bomify": buildinfo.GetBuildInfo().Version}},
			Metadata: &slsa.BuildMetadata{
				InvocationId: os.Getenv(InvocationIDEnv),
				StartedOn:    timestamppb.New(r.started.Truncate(time.Second)),
				FinishedOn:   timestamppb.New(time.Now().Truncate(time.Second)),
			},
		},
	}
	if err := p.Validate(); err != nil {
		return fmt.Errorf("provenance: %w", err)
	}
	data, err := protojson.MarshalOptions{Multiline: true}.Marshal(p)
	if err != nil {
		return fmt.Errorf("encode provenance: %w", err)
	}
	return fsutil.WriteFileAtomic(layout.Provenance(baseDir, sbomHash), data)
}

// externalParameters are what the user asked bomify build to do: the
// SBOM it built, by digest, and the tags it gave the build. Their schema
// is BuildType's to define.
func externalParameters(sbomHash string, tags []string) (*structpb.Struct, error) {
	params := map[string]any{"sbom": map[string]any{"digest": map[string]any{"sha256": strings.ToLower(sbomHash)}}}
	if len(tags) > 0 {
		list := make([]any, len(tags))
		for i, tag := range tags {
			list[i] = tag
		}
		params["tags"] = list
	}
	return structpb.NewStruct(params)
}

// Read returns baseDir's provenance for the build of sbomHash; ok is false
// if that build recorded none.
func Read(baseDir, sbomHash string) (p *slsa.Provenance, ok bool, err error) {
	data, err := os.ReadFile(layout.Provenance(baseDir, sbomHash))
	if os.IsNotExist(err) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	p = &slsa.Provenance{}
	if err := protojson.Unmarshal(data, p); err != nil {
		return nil, false, fmt.Errorf("parse provenance %s: %w", layout.Provenance(baseDir, sbomHash), err)
	}
	return p, true, nil
}

// NewStatement returns p as an in-toto statement whose subject is the
// artifact name with the given sha256 digest. Its encoding is compact and
// deterministic, so the same provenance always hashes the same (see
// AnnotationStatement).
func NewStatement(p *slsa.Provenance, name, sha256 string) ([]byte, error) {
	predicate, err := toStruct(p)
	if err != nil {
		return nil, err
	}
	s := &intoto.Statement{
		Type:          intoto.StatementTypeUri,
		Subject:       []*intoto.ResourceDescriptor{{Name: name, Digest: digest(sha256)}},
		PredicateType: PredicateType,
		Predicate:     predicate,
	}
	if err := s.Validate(); err != nil {
		return nil, fmt.Errorf("provenance statement: %w", err)
	}
	data, err := protojson.Marshal(s)
	if err != nil {
		return nil, fmt.Errorf("encode provenance statement: %w", err)
	}
	// protojson's whitespace deliberately varies between builds of bomify.
	var buf bytes.Buffer
	if err := json.Compact(&buf, data); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// toStruct converts p to the generic Struct a Statement's predicate is.
func toStruct(p *slsa.Provenance) (*structpb.Struct, error) {
	data, err := protojson.Marshal(p)
	if err != nil {
		return nil, fmt.Errorf("encode provenance: %w", err)
	}
	s := &structpb.Struct{}
	if err := protojson.Unmarshal(data, s); err != nil {
		return nil, fmt.Errorf("encode provenance: %w", err)
	}
	return s, nil
}

func digest(sha256 string) map[string]string {
	if sha256 == "" {
		return nil
	}
	return map[string]string{"sha256": strings.ToLower(sha256)}
}
