package cmd

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/spf13/cobra"

	"github.com/alejandro-velasco/bomify/internal/build"
	"github.com/alejandro-velasco/bomify/internal/logging"
	"github.com/alejandro-velasco/bomify/internal/plugin"
	"github.com/alejandro-velasco/bomify/internal/security"
)

const securityShort = "Security scanning commands"

func securityCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "security",
		Short: securityShort,
	}

	cmd.AddCommand(securityScanCmd())
	cmd.AddCommand(securityPruneCmd())

	return cmd
}

const securityScanShort = "Scan a built package's components for vulnerabilities via a security scanning plugin"

const securityScanLong = `Scan resolves <tag> to a package a prior "bomify build" (or "bomify
pull"/"bomify load") recorded locally, then scans every component that
package's SBOM describes through a single "bomify-plugin-<type>" binary —
<type> names the scanning tool itself (e.g. "grype"), not a purl type or
deployment medium, since any scanner can in principle scan any component.

bomify first asks the plugin, once, which component purl types and scan
categories it supports ("security supported-components"). Any component
whose purl type isn't in that list is skipped; every other component is
scanned via "security scan --purl <purl>", once per component, up to
--concurrency at a time: the same per-component, concurrent dispatch
"bomify build"/"bomify distribute" use, just for scanning instead of
pulling/pushing.

Each component's result is written as its own CycloneDX vulnerability
report, <data-dir>/vulnerabilities/<purl-hash>.json — keyed by the same
purl hash as that component's pull manifest and layer, so a component
shared by two packages shares one report too, and scanning either
package refreshes it for both. A report's metadata component is the
scanned component itself; for a component the plugin had to unpack to
scan at all (e.g. cataloging an OCI image's contents), the pieces it
found are the report's top-level components, and each vulnerability's
"affects" names the specific piece(s) affected. See
plugins/SECURITY-CONTRACT.md for the full contract.`

const securityScanExample = `  # Scan the package tagged myapp:latest for vulnerabilities with grype
  bomify security scan grype myapp:latest

  # Scan up to 4 components concurrently
  bomify security scan grype myapp:latest --concurrency 4`

type securityScanOptions struct {
	scanType    string
	tag         string
	concurrency int
}

func securityScanCmd() *cobra.Command {
	opts := &securityScanOptions{}

	cmd := &cobra.Command{
		Use:     "scan <type> <tag>",
		Short:   securityScanShort,
		Long:    securityScanLong,
		Example: securityScanExample,
		Args:    cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			opts.scanType, opts.tag = args[0], args[1]
			if err := runSecurityScan(opts, logging.FromContext(cmd.Context())); err != nil {
				return fmt.Errorf("security scan: %w", err)
			}
			return nil
		},
		ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
			if len(args) != 1 {
				return nil, cobra.ShellCompDirectiveNoFileComp
			}
			return completeLocalTags(cmd, args, toComplete)
		},
	}

	cmd.Flags().IntVarP(&opts.concurrency, "concurrency", "c", 1, "number of components to scan concurrently")

	return cmd
}

func runSecurityScan(opts *securityScanOptions, logger *slog.Logger) error {
	sbomHash, err := build.ResolveTag(dataDir, opts.tag)
	if err != nil {
		return err
	}

	path, err := plugin.Find(plugin.Dir(dataDir), opts.scanType)
	if err != nil {
		return err
	}

	capabilities, err := plugin.SupportedComponents(path, logger)
	if err != nil {
		return err
	}
	logger.Info("plugin capabilities", "types", capabilities.Types, "scans", capabilities.Scans)
	supportedTypes := make(map[string]bool, len(capabilities.Types))
	for _, t := range capabilities.Types {
		supportedTypes[t] = true
	}

	// The same purl listed twice in one SBOM maps to the same report, so
	// only its first occurrence is scanned.
	var claimed sync.Map

	if err := forEachComponent(build.ManifestPath(dataDir, sbomHash), logger, opts.concurrency, func(component cdx.Component, log *slog.Logger) error {
		kind, err := plugin.Detect(component)
		if err != nil {
			log.Warn("skipping component: cannot determine its kind", "error", err)
			return nil
		}
		if !supportedTypes[kind] {
			log.Info("skipping component: unsupported by this scanner", "kind", kind)
			return nil
		}

		purlHash := plugin.PurlHash(component)
		if _, dup := claimed.LoadOrStore(purlHash, true); dup {
			log.Debug("skipping component: purl already scanned", "purl", component.PackageURL)
			return nil
		}

		result, err := plugin.Scan(path, component, log)
		if err != nil {
			return err
		}

		reportPath, err := security.WriteReport(dataDir, component, security.NewReport(component, result, opts.scanType, time.Now()))
		if err != nil {
			return err
		}
		log.Info("scan complete", "vulnerabilities", len(result.Vulnerabilities), "components", len(result.Components), "report", reportPath)
		return nil
	}); err != nil {
		return err
	}

	return nil
}

const securityPruneShort = "Delete stale vulnerability report referrers of a package in a registry"

const securityPruneLong = `Prune deletes all but the newest --keep vulnerability report referrers
attached to the package <ref> resolves to in its registry, each along
with anything referring to it in turn (typically its signature). The
package itself, its own signatures, and anything else attached to it are
left alone.

"bomify push" already does this after attaching new reports (see its
--keep-reports); prune is for retrying that when it couldn't, or for
cleaning up a package without pushing it again. Unlike push, prune fails
if any stale referrer couldn't be deleted — e.g. because the registry
refuses manifest deletes altogether.`

const securityPruneExample = `  # Keep only the newest vulnerability reports of a pushed package
  bomify security prune registry.example.com/myapp:latest

  # Keep the three newest
  bomify security prune registry.example.com/myapp:latest --keep 3`

func securityPruneCmd() *cobra.Command {
	var keep int

	cmd := &cobra.Command{
		Use:     "prune <ref>",
		Short:   securityPruneShort,
		Long:    securityPruneLong,
		Example: securityPruneExample,
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if keep < 1 {
				return fmt.Errorf("security prune: --keep must be at least 1")
			}
			if err := runSecurityPrune(cmd.Context(), args[0], keep, logging.FromContext(cmd.Context())); err != nil {
				return fmt.Errorf("security prune: %w", err)
			}
			return nil
		},
	}

	cmd.Flags().IntVar(&keep, "keep", 1, "number of newest vulnerability report referrers to keep")

	return cmd
}

func runSecurityPrune(ctx context.Context, ref string, keep int, logger *slog.Logger) error {
	repo, err := newRepository(ref)
	if err != nil {
		return err
	}

	manifest, err := repo.Resolve(ctx, ref)
	if err != nil {
		return fmt.Errorf("resolve %s: %w", ref, err)
	}

	deleted, err := security.PruneReferrers(ctx, repo, manifest, keep)
	for _, d := range deleted {
		logger.Info("stale referrer deleted", "digest", d.Digest.String(), "artifactType", d.ArtifactType)
	}
	if err != nil {
		return err
	}
	if len(deleted) == 0 {
		logger.Info("nothing to prune", "reference", ref)
	}
	return nil
}
