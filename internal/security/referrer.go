package security

import (
	"context"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
	"time"

	cdx "github.com/CycloneDX/cyclonedx-go"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2"
	"oras.land/oras-go/v2/content"
	"oras.land/oras-go/v2/errdef"
	"oras.land/oras-go/v2/registry"

	"github.com/alejandro-velasco/bomify/internal/layout"
	"github.com/alejandro-velasco/bomify/internal/oci/transfer"
	"github.com/alejandro-velasco/bomify/internal/sbom"
)

// AnnotationScanPlugin is the report referrer annotation naming the
// scanning plugin(s) that produced its reports, purely informational.
const AnnotationScanPlugin = "land.bomify.scan.plugin"

// AttachedReport is one component's vulnerability report attached to a
// package.
type AttachedReport struct {
	Purl string
	Hash string
}

// Attach pushes the local vulnerability report (see WriteReport) of
// every component in components that has one into target, as the layers
// of a single VulnerabilityReportsArtifactType referrer whose subject is
// the package manifest, manifest. It returns that referrer and the
// reports it carries, in components' order; ok is false, and nothing is
// pushed, when no component has a local report at all.
//
// The referrer is built only from the reports themselves — its created
// annotation is the newest report's scan time, not the time of the push
// — so pushing an unchanged package with unchanged reports again
// produces the very same referrer rather than stacking up another.
func Attach(ctx context.Context, target oras.Target, manifest ocispec.Descriptor, baseDir string, components []cdx.Component, progress transfer.ProgressFunc) (referrer ocispec.Descriptor, attached []AttachedReport, ok bool, err error) {
	var (
		layers   []ocispec.Descriptor
		newest   time.Time
		scanners []string
		seen     = map[string]bool{}
	)
	for _, component := range components {
		purlHash := layout.PurlHash(component.PackageURL)
		if seen[purlHash] {
			continue
		}
		seen[purlHash] = true

		reportPath := layout.Report(baseDir, purlHash)
		data, err := os.ReadFile(reportPath)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return ocispec.Descriptor{}, nil, false, fmt.Errorf("read vulnerability report %s: %w", reportPath, err)
		}

		if report, err := sbom.LoadBytes(data); err == nil {
			scannedAt, scanner := reportProvenance(report)
			if scannedAt.After(newest) {
				newest = scannedAt
			}
			if scanner != "" && !slices.Contains(scanners, scanner) {
				scanners = append(scanners, scanner)
			}
		}

		purl := component.PackageURL
		label := transfer.Label(purl, purlHash)
		desc, err := transfer.PushBytes(ctx, target, data, transfer.VulnerabilityReportMediaType, "vulnerability report: "+label, progress)
		if err != nil {
			return ocispec.Descriptor{}, nil, false, fmt.Errorf("push vulnerability report %s: %w", label, err)
		}
		desc.Annotations = map[string]string{
			ocispec.AnnotationTitle: purlHash + ".json",
			transfer.AnnotationPurl: purl,
		}
		layers = append(layers, desc)
		attached = append(attached, AttachedReport{Purl: purl, Hash: desc.Digest.Encoded()})
	}
	if len(layers) == 0 {
		return ocispec.Descriptor{}, nil, false, nil
	}

	if newest.IsZero() {
		newest = time.Unix(0, 0)
	}
	annotations := map[string]string{
		ocispec.AnnotationCreated: newest.UTC().Format(time.RFC3339),
	}
	if len(scanners) > 0 {
		slices.Sort(scanners)
		annotations[AnnotationScanPlugin] = strings.Join(scanners, ",")
	}

	// Built only from the reports themselves, so an identical referrer
	// already in target — the same reports pushed again — is left alone
	// (see transfer.PushReferrer).
	referrer, err = transfer.PushReferrer(ctx, target, manifest, transfer.VulnerabilityReportsArtifactType, layers, annotations, "vulnerability reports")
	if err != nil {
		return ocispec.Descriptor{}, nil, false, err
	}
	return referrer, attached, true, nil
}

// reportProvenance returns when report was scanned and by which plugin,
// as NewReport recorded them; either is its zero value if the report
// doesn't say (e.g. one written before bomify recorded them).
func reportProvenance(report *cdx.BOM) (scannedAt time.Time, scanner string) {
	if report.Metadata == nil {
		return time.Time{}, ""
	}
	scannedAt, _ = time.Parse(time.RFC3339, report.Metadata.Timestamp)
	if tools := report.Metadata.Tools; tools != nil && tools.Components != nil && len(*tools.Components) > 0 {
		scanner = (*tools.Components)[0].Name
	}
	return scannedAt, scanner
}

// ReportReferrers lists manifest's vulnerability report referrers in target,
// newest first (see transfer.Referrers).
func ReportReferrers(ctx context.Context, target content.ReadOnlyStorage, manifest ocispec.Descriptor) ([]ocispec.Descriptor, error) {
	return transfer.Referrers(ctx, target, manifest, transfer.VulnerabilityReportsArtifactType)
}

// FetchReports returns the report layers a vulnerability report referrer
// carries.
func FetchReports(ctx context.Context, target content.ReadOnlyStorage, referrer ocispec.Descriptor) ([]ocispec.Descriptor, error) {
	return transfer.ReferrerLayers(ctx, target, referrer, transfer.VulnerabilityReportMediaType)
}

// PruneTarget is a target PruneReferrers can list and delete referrers
// in, such as a remote.Repository.
type PruneTarget interface {
	content.ReadOnlyGraphStorage
	content.Deleter
}

// PruneReferrers deletes all but the newest keep of manifest's
// vulnerability report referrers in target (see ReportReferrers), each along
// with anything referring to it in turn — typically its signature — so
// deleting a report never leaves an orphaned signature behind. keep < 1
// deletes nothing. Only VulnerabilityReportsArtifactType referrers are
// ever candidates: the package's own signatures, and anything any other
// tool attached, are left alone.
//
// Deletion is best-effort: it carries on past a referrer it fails to
// delete (plenty of registries refuse manifest deletes outright), and
// returns every referrer it did delete alongside every failure, joined.
func PruneReferrers(ctx context.Context, target PruneTarget, manifest ocispec.Descriptor, keep int) (deleted []ocispec.Descriptor, err error) {
	if keep < 1 {
		return nil, nil
	}

	referrers, err := ReportReferrers(ctx, target, manifest)
	if err != nil {
		return nil, err
	}
	if len(referrers) <= keep {
		return nil, nil
	}

	var failures []error
	for _, stale := range referrers[keep:] {
		dependents, err := registry.Referrers(ctx, target, stale, "")
		if err != nil {
			failures = append(failures, fmt.Errorf("list referrers of %s: %w", stale.Digest, err))
			continue
		}

		var dependentFailed bool
		for _, dependent := range dependents {
			if err := deleteIfExists(ctx, target, dependent); err != nil {
				failures = append(failures, fmt.Errorf("delete %s (referring to %s): %w", dependent.Digest, stale.Digest, err))
				dependentFailed = true
				continue
			}
			deleted = append(deleted, dependent)
		}
		// Deleting the report while something still refers to it would
		// orphan that; leave both for a later prune instead.
		if dependentFailed {
			continue
		}

		if err := deleteIfExists(ctx, target, stale); err != nil {
			failures = append(failures, fmt.Errorf("delete %s: %w", stale.Digest, err))
			continue
		}
		deleted = append(deleted, stale)
	}

	return deleted, errors.Join(failures...)
}

// deleteIfExists deletes desc from target, treating it already being gone
// as success: some targets (e.g. a local content/oci.Store, garbage
// collecting a report once its signature is deleted) remove it on their
// own.
func deleteIfExists(ctx context.Context, target content.Deleter, desc ocispec.Descriptor) error {
	if err := target.Delete(ctx, desc); err != nil && !errors.Is(err, errdef.ErrNotFound) {
		return err
	}
	return nil
}
