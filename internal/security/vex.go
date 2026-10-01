package security

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"slices"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/alejandro-velasco/bomify/internal/sbom"
	"github.com/openvex/go-vex/pkg/vex"
)

// VEX is a set of Vulnerability Exploitability eXchange statements, from
// any number of OpenVEX, CSAF VEX, and CycloneDX VEX documents (see
// LoadVEX): each says whether one vulnerability affects one product — a
// component, by purl — and why. A Gate consults them before failing a
// package, so a vulnerability shown not to affect the component it was
// found in (or already fixed there) doesn't fail it.
//
// Statements are held as go-vex's OpenVEX model, whatever format they
// came from, so matching them — purls included, where a statement's
// purl without a version or qualifiers matches any version or
// qualifiers — is go-vex's own.
type VEX struct {
	// statements are in precedence order: a later one supersedes an
	// earlier one about the same vulnerability and product.
	statements []SourcedStatement
}

// SourcedStatement is a VEX statement and where it came from: the
// document's path, or ReportSource for an analysis a scan report
// carried itself.
type SourcedStatement struct {
	vex.Statement
	Source string
}

// ReportSource is the Source of a statement taken from a scan report's
// own analysis rather than a VEX document.
const ReportSource = "scan report"

// exemptStatuses are the OpenVEX statuses under which a vulnerability
// doesn't count against a component; "affected" and
// "under_investigation" do.
var exemptStatuses = map[vex.Status]bool{
	vex.StatusNotAffected: true,
	vex.StatusFixed:       true,
}

// cdxStatuses maps CycloneDX analysis states onto the OpenVEX status
// meaning the same thing.
var cdxStatuses = map[cdx.ImpactAnalysisState]vex.Status{
	cdx.IASNotAffected:          vex.StatusNotAffected,
	cdx.IASFalsePositive:        vex.StatusNotAffected,
	cdx.IASResolved:             vex.StatusFixed,
	cdx.IASResolvedWithPedigree: vex.StatusFixed,
	cdx.IASExploitable:          vex.StatusAffected,
	cdx.IASInTriage:             vex.StatusUnderInvestigation,
}

// VEXDocument is a VEX document's content and a name for it: its path,
// a stored name, or where a package's publisher attached it. The name
// labels the document's statements (see SourcedStatement).
type VEXDocument struct {
	Name string
	Data []byte
}

// LoadVEX reads every document in paths, in order, as LoadVEXDocuments
// does, each named by its path.
func LoadVEX(paths []string) (*VEX, error) {
	docs := make([]VEXDocument, 0, len(paths))
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("load VEX %s: %w", path, err)
		}
		docs = append(docs, VEXDocument{Name: path, Data: data})
	}
	return LoadVEXDocuments(docs)
}

// LoadVEXDocuments reads every one of docs, in order: OpenVEX (JSON or
// YAML, any version) and CSAF are read by go-vex; CycloneDX VEX — a
// CycloneDX JSON BOM whose vulnerabilities carry an analysis — is
// converted into the same statements. When several statements cover the
// same vulnerability in the same component, the last one wins:
// documents in the order given, and, within an OpenVEX document,
// statements by timestamp.
func LoadVEXDocuments(docs []VEXDocument) (*VEX, error) {
	v := &VEX{}
	for _, doc := range docs {
		statements, err := loadStatements(doc.Data)
		if err != nil {
			return nil, fmt.Errorf("load VEX %s: %w", doc.Name, err)
		}
		for _, s := range statements {
			v.statements = append(v.statements, SourcedStatement{Statement: s, Source: doc.Name})
		}
	}
	return v, nil
}

// CombineVEX returns the statements of first and then of then, so that
// where they disagree then's win. Either may be nil.
func CombineVEX(first, then *VEX) *VEX {
	if first == nil {
		return then
	}
	if then == nil {
		return first
	}
	return &VEX{statements: append(slices.Clone(first.statements), then.statements...)}
}

func loadStatements(data []byte) ([]vex.Statement, error) {
	var probe struct {
		BOMFormat string `json:"bomFormat"`
	}
	if json.Unmarshal(data, &probe) == nil && probe.BOMFormat == "CycloneDX" {
		return cycloneDXStatements(data)
	}

	// go-vex only detects a document's format (OpenVEX versions, YAML,
	// CSAF) when opening a file.
	f, err := os.CreateTemp("", "bomify-vex-*")
	if err != nil {
		return nil, fmt.Errorf("create temp file: %w", err)
	}
	defer os.Remove(f.Name())
	_, writeErr := f.Write(data)
	if err := errors.Join(writeErr, f.Close()); err != nil {
		return nil, fmt.Errorf("write temp file: %w", err)
	}

	doc, err := vex.Open(f.Name())
	if err != nil {
		return nil, fmt.Errorf("neither CycloneDX VEX nor a document go-vex reads (OpenVEX, CSAF): %w", err)
	}
	statements := doc.Statements
	if doc.Timestamp != nil {
		vex.SortStatements(statements, *doc.Timestamp)
	}
	return statements, nil
}

// cycloneDXStatements converts a CycloneDX VEX document's analyzed
// vulnerabilities into OpenVEX statements.
func cycloneDXStatements(data []byte) ([]vex.Statement, error) {
	var bom cdx.BOM
	if err := cdx.NewBOMDecoder(bytes.NewReader(data), cdx.BOMFileFormatJSON).Decode(&bom); err != nil {
		return nil, err
	}
	if bom.Vulnerabilities == nil {
		return nil, nil
	}

	// A VEX document's "affects" may name its own components by bom-ref,
	// or by BOM-Link ("urn:cdx:<serial>/<version>#<bom-ref>"), rather than
	// by purl; resolve those to purls where it says what they are.
	components := sbom.Components(bom.Components)
	if bom.Metadata != nil && bom.Metadata.Component != nil {
		components = append(components, *bom.Metadata.Component)
	}
	purlByRef := purlsByBOMRef(components)

	var statements []vex.Statement
	for _, vuln := range *bom.Vulnerabilities {
		s, ok := analysisStatement(vuln)
		if !ok || vuln.Affects == nil {
			continue
		}
		for _, affects := range *vuln.Affects {
			ref := affects.Ref
			// A BOM-Link to a whole BOM, with no element, names no
			// component; leave it as is, matching nothing.
			if link, err := cdx.ParseBOMLink(ref); err == nil && link.Reference() != "" {
				ref = link.Reference()
			}
			if purl, ok := purlByRef[ref]; ok {
				ref = purl
			}
			s.Products = append(s.Products, vex.Product{Component: vex.Component{ID: ref}})
		}
		statements = append(statements, s)
	}
	return statements, nil
}

// analysisStatement converts vuln's CycloneDX analysis into an OpenVEX
// statement about it, with no products — the caller knows what it's
// about. ok is false if vuln carries no analysis, or one in a state
// OpenVEX has no equivalent for.
func analysisStatement(vuln cdx.Vulnerability) (s vex.Statement, ok bool) {
	if vuln.Analysis == nil {
		return vex.Statement{}, false
	}
	status, ok := cdxStatuses[vuln.Analysis.State]
	if !ok {
		return vex.Statement{}, false
	}

	// vulnerabilityIDs lists vuln's own ID first, then its related IDs:
	// the first becomes the statement's Name, the rest its Aliases.
	ids := vulnerabilityIDs(vuln)
	ownID, relatedIDs := ids[0], ids[1:]

	s = vex.Statement{
		Vulnerability: vex.Vulnerability{Name: vex.VulnerabilityID(ownID)},
		Status:        status,
		// CycloneDX's justifications aren't OpenVEX's; kept verbatim,
		// since bomify only reports them, never branches on them.
		Justification:   vex.Justification(vuln.Analysis.Justification),
		ImpactStatement: vuln.Analysis.Detail,
	}
	for _, id := range relatedIDs {
		s.Vulnerability.Aliases = append(s.Vulnerability.Aliases, vex.VulnerabilityID(id))
	}
	return s, true
}

// purlsByBOMRef maps the bom-ref of every component in components — and
// of every component nested inside them — to its purl, for resolving
// references (e.g. a vulnerability's "affects") that name a component by
// bom-ref. Components without both are left out.
func purlsByBOMRef(components []cdx.Component) map[string]string {
	purlByRef := map[string]string{}
	var index func([]cdx.Component)
	index = func(cs []cdx.Component) {
		for _, c := range cs {
			if c.BOMRef != "" && c.PackageURL != "" {
				purlByRef[c.BOMRef] = c.PackageURL
			}
			index(sbom.Components(c.Components))
		}
	}
	index(components)
	return purlByRef
}

// vulnerabilityIDs returns vuln's own ID, always first, followed by
// every related ID it lists (e.g. the CVE behind a GHSA advisory), so a
// VEX statement naming any of them applies.
func vulnerabilityIDs(vuln cdx.Vulnerability) []string {
	ids := []string{vuln.ID}
	if vuln.References != nil {
		for _, ref := range *vuln.References {
			if ref.ID != "" {
				ids = append(ids, ref.ID)
			}
		}
	}
	return ids
}

// exempts reports whether v exempts vuln — found in component, and
// affecting, per its "affects", the pieces named there — from failing a
// gate, and by which statement. purlByRef resolves an "affects" ref that
// names a piece by bom-ref (see purlsByBOMRef over the report's
// components). Every piece vuln affects must
// be exempted: a statement that only clears one package in an image
// leaves the vulnerability standing if another package there is still
// affected. A statement covers a piece when its product is the scanned
// component with that piece as a subcomponent (or no subcomponents at
// all), or is the piece itself. A report's own analysis (e.g. one a
// scanner recorded) counts first, as if it were the earliest statement.
// The statement returned is the one that decided the last piece.
func (v *VEX) exempts(component cdx.Component, purlByRef map[string]string, vuln cdx.Vulnerability) (SourcedStatement, bool) {
	// Each piece vuln affects, by purl where the report says what it is.
	var targets []string
	if vuln.Affects != nil {
		for _, a := range *vuln.Affects {
			ref := a.Ref
			if purl, ok := purlByRef[ref]; ok {
				ref = purl
			}
			targets = append(targets, ref)
		}
	}
	// With no "affects" at all, it can only mean the component itself.
	if len(targets) == 0 {
		targets = []string{component.PackageURL}
	}

	var initial *SourcedStatement
	if s, ok := analysisStatement(vuln); ok {
		initial = &SourcedStatement{Statement: s, Source: ReportSource}
	}

	ids := vulnerabilityIDs(vuln)
	var last SourcedStatement
	for _, target := range targets {
		// Statements are in precedence order, so the last one covering
		// target has the final say; search from the end and stop there.
		// With none, the report's own analysis (if any) stands.
		decided := initial
		if v != nil {
			for i := len(v.statements) - 1; i >= 0; i-- {
				if v.statements[i].covers(ids, component.PackageURL, target) {
					decided = &v.statements[i]
					break
				}
			}
		}
		if decided == nil || !exemptStatuses[decided.Status] {
			return SourcedStatement{}, false
		}
		last = *decided
	}
	return last, true
}

// covers reports whether s is about any of ids in target, one piece of
// the scanned component componentPurl (the same thing, for a component
// scanned directly).
func (s SourcedStatement) covers(ids []string, componentPurl, target string) bool {
	for _, id := range ids {
		// The statement's product is the scanned component (e.g. the
		// image), and it either names target among its subcomponents or
		// names none, covering everything inside.
		aboutComponent := s.Matches(id, componentPurl, []string{target})
		// The statement's product is target itself, wherever it's found.
		aboutTarget := s.Matches(id, target, nil)

		if aboutComponent || aboutTarget {
			return true
		}
	}
	return false
}
