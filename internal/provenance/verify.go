package provenance

import (
	"fmt"

	slsa "github.com/in-toto/attestation/go/predicates/provenance/v1"
	intoto "github.com/in-toto/attestation/go/v1"
	"google.golang.org/protobuf/encoding/protojson"
)

// Check requires statement to be bomify build provenance, as NewStatement
// writes it, about the package whose manifest has SHA-256 manifestSHA256
// and whose SBOM has SHA-256 sbomSHA256: a valid in-toto statement of
// PredicateType naming that manifest among its subjects, whose predicate
// is valid SLSA provenance of BuildType, built by BuilderID, from that
// SBOM. The subject's name is not checked, since copying the package to
// another repository doesn't change what was built.
func Check(statement []byte, manifestSHA256, sbomSHA256 string) error {
	s := &intoto.Statement{}
	if err := protojson.Unmarshal(statement, s); err != nil {
		return fmt.Errorf("parse statement: %w", err)
	}
	if err := s.Validate(); err != nil {
		return fmt.Errorf("statement: %w", err)
	}
	if s.GetPredicateType() != PredicateType {
		return fmt.Errorf("predicate type is %q, want %q", s.GetPredicateType(), PredicateType)
	}
	named := false
	for _, subject := range s.GetSubject() {
		named = named || subject.GetDigest()["sha256"] == manifestSHA256
	}
	if !named {
		return fmt.Errorf("statement is not about package sha256:%s", manifestSHA256)
	}

	p := &slsa.Provenance{}
	if err := fromStruct(s.GetPredicate(), p); err != nil {
		return fmt.Errorf("parse provenance: %w", err)
	}
	if err := p.Validate(); err != nil {
		return fmt.Errorf("provenance: %w", err)
	}
	if got := p.GetBuildDefinition().GetBuildType(); got != BuildType {
		return fmt.Errorf("build type is %q, want %q", got, BuildType)
	}
	if got := p.GetRunDetails().GetBuilder().GetId(); got != BuilderID {
		return fmt.Errorf("builder is %q, want %q", got, BuilderID)
	}
	rd := &intoto.ResourceDescriptor{}
	if err := fromStruct(p.GetBuildDefinition().GetExternalParameters().GetFields()["sbom"].GetStructValue(), rd); err != nil {
		return fmt.Errorf("externalParameters.sbom: %w", err)
	}
	if sbom := rd.GetDigest()["sha256"]; sbom != sbomSHA256 {
		return fmt.Errorf("provenance is for SBOM sha256:%s, but the package's is sha256:%s", sbom, sbomSHA256)
	}
	return nil
}
