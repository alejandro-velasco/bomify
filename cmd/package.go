package cmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/spf13/cobra"

	"github.com/alejandro-velasco/bomify/internal/build"
	"github.com/alejandro-velasco/bomify/internal/logging"
	"github.com/alejandro-velasco/bomify/internal/oci/pull"
	"github.com/alejandro-velasco/bomify/internal/plugin"
	"github.com/alejandro-velasco/bomify/internal/sbom"
	"github.com/alejandro-velasco/bomify/internal/security"
)

const packageShort = "Manage individual bomify packages"

func packageCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "package",
		Short: packageShort,
	}

	cmd.AddCommand(packagePruneCmd())
	cmd.AddCommand(packageRemoveCmd())
	cmd.AddCommand(packageManifestCmd())
	cmd.AddCommand(packageVulnerabilitiesCmd())

	// Aliases for the top-level commands relating to package management
	cmd.AddCommand(buildCmd())
	cmd.AddCommand(pushCmd())
	cmd.AddCommand(pullCmd())
	cmd.AddCommand(tagCmd())
	cmd.AddCommand(saveCmd())
	cmd.AddCommand(loadCmd())
	cmd.AddCommand(distributeCmd())

	return cmd
}

const packagePruneShort = "Remove packages not associated with any tag"

const packagePruneLong = `Prune removes every manifest, layer, and vulnerability report in the
data directory that isn't reachable from a tag currently recorded in
repositories.json. A component still used by any tagged package, even
one also used by an otherwise-unreferenced package, is left alone.`

const packagePruneExample = `  # Remove every untagged manifest, layer, and vulnerability report
  bomify package prune`

func packagePruneCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "prune",
		Short:   packagePruneShort,
		Long:    packagePruneLong,
		Example: packagePruneExample,
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := runPackagePrune(cmd); err != nil {
				return fmt.Errorf("package prune: %w", err)
			}
			return nil
		},
	}

	return cmd
}

func runPackagePrune(cmd *cobra.Command) error {
	logger := logging.FromContext(cmd.Context())

	result, err := build.Prune(dataDir)
	if err != nil {
		return err
	}

	for _, item := range result.Removed {
		logger.Info("removed", "kind", item.Kind, "path", item.Path)
	}
	for _, hash := range result.Skipped {
		logger.Info("skipped (pull in progress)", "hash", hash)
	}
	for _, hash := range result.Unprotected {
		logger.Warn("could not parse this build's manifest; its components could not be protected from pruning", "hash", hash)
	}

	fmt.Fprintf(cmd.OutOrStdout(), "Removed %d item(s)\n", len(result.Removed))

	return nil
}

const packageManifestShort = "Print a remote package's CycloneDX manifest"

const packageManifestLong = `Manifest fetches <reference> from an OCI registry and writes its
aggregate CycloneDX SBOM manifest (the artifact's config blob)
verbatim to stdout, without pulling any of its layers or writing
anything to the data directory.`

const packageManifestExample = `  # Print the manifest for a tagged reference
  bomify package manifest registry.example.com/myapp:latest

  # Print the manifest for a digest reference
  bomify package manifest registry.example.com/myapp@sha256:abcdef...`

func packageManifestCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "manifest <reference>",
		Short:   packageManifestShort,
		Long:    packageManifestLong,
		Example: packageManifestExample,
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := runPackageManifest(cmd, args[0]); err != nil {
				return fmt.Errorf("package manifest: %w", err)
			}
			return nil
		},
	}

	return cmd
}

func runPackageManifest(cmd *cobra.Command, ref string) error {
	repo, err := newRepository(ref)
	if err != nil {
		return err
	}

	data, err := pull.Manifest(cmd.Context(), repo, ref)
	if err != nil {
		return err
	}

	_, err = cmd.OutOrStdout().Write(data)
	return err
}

const packageRemoveShort = "Remove packages by tag"

const packageRemoveLong = `Remove untags each given <tag> and reclaims any manifest or component
no longer used by a remaining tag. Also available as the top-level
shorthand "bomify rmp".`

const packageRemoveExample = `  # Remove a single tagged package
  bomify package remove myapp:latest

  # Remove several at once
  bomify package remove myapp:v1 myapp:v2`

func packageRemoveCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "remove <tag>...",
		Aliases: []string{"rm"},
		Short:   packageRemoveShort,
		Long:    packageRemoveLong,
		Example: packageRemoveExample,
		Args:    cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := runPackageRemove(cmd, args); err != nil {
				return fmt.Errorf("package remove: %w", err)
			}
			return nil
		},
		ValidArgsFunction: completeLocalTags,
	}

	return cmd
}

const rmpShort = "Remove packages by tag (shorthand for \"bomify package remove\")"

const rmpExample = `  # Remove a single tagged package
  bomify rmp myapp:latest

  # Remove several at once
  bomify rmp myapp:v1 myapp:v2`

func rmpCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "rmp <tag>...",
		Short:   rmpShort,
		Example: rmpExample,
		Args:    cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := runPackageRemove(cmd, args); err != nil {
				return fmt.Errorf("rmp: %w", err)
			}
			return nil
		},
		ValidArgsFunction: completeLocalTags,
	}

	return cmd
}

func runPackageRemove(cmd *cobra.Command, tags []string) error {
	logger := logging.FromContext(cmd.Context())

	var failed []string
	for _, tag := range tags {
		if err := build.RemoveTag(dataDir, tag); err != nil {
			logger.Error("failed to remove", "tag", tag, "error", err)
			failed = append(failed, tag)
			continue
		}
		fmt.Fprintln(cmd.OutOrStdout(), tag)
	}

	if err := pruneAfterRemove(logger); err != nil {
		return err
	}

	if len(failed) > 0 {
		return fmt.Errorf("failed to remove: %s", strings.Join(failed, ", "))
	}

	return nil
}

func pruneAfterRemove(logger *slog.Logger) error {
	result, err := build.Prune(dataDir)
	if err != nil {
		return fmt.Errorf("prune after remove: %w", err)
	}

	for _, item := range result.Removed {
		logger.Info("removed", "kind", item.Kind, "path", item.Path)
	}
	for _, hash := range result.Skipped {
		logger.Info("skipped (pull in progress)", "hash", hash)
	}
	for _, hash := range result.Unprotected {
		logger.Warn("could not parse this build's manifest; its components could not be protected from pruning", "hash", hash)
	}

	return nil
}

const packageVulnerabilitiesShort = "Print a package's component vulnerability reports"

const packageVulnerabilitiesLong = `Vulnerabilities resolves <tag> to a package a prior "bomify build" (or
"bomify pull"/"bomify load") recorded locally, then writes a JSON array
to stdout — parsable straight through "jq", unlike the single raw
document "bomify package manifest" writes — with one element per
component: its vulnerability report exactly as it sits at
"<data-dir>/vulnerabilities/<purl-hash>.json" (see "bomify security
scan"), in the SBOM's own component order. A component with no report
(never scanned, or scanned by a plugin that doesn't support its purl
type) is silently skipped, and a purl the SBOM lists more than once is
only included once.

--purl narrows this down to specific components; pass it more than
once for more than one. Without it, every component the SBOM describes
is considered.

Nothing but that JSON array is ever written to stdout — no log lines,
so a "--purl" that matches nothing in the SBOM is reported as a
warning on stderr rather than printed inline.`

const packageVulnerabilitiesExample = `  # Print every component's vulnerability report for a package
  bomify package vulnerabilities myapp:latest

  # Print only specific components' reports
  bomify package vulnerabilities myapp:latest --purl pkg:oci/nginx@1.27 --purl pkg:npm/lodash@4.17.15

  # Pipe into jq, e.g. to list every reported vulnerability ID
  bomify package vulnerabilities myapp:latest | jq '.[].vulnerabilities[].id'`

type packageVulnerabilitiesOptions struct {
	tag   string
	purls []string
}

func packageVulnerabilitiesCmd() *cobra.Command {
	opts := &packageVulnerabilitiesOptions{}

	cmd := &cobra.Command{
		Use:     "vulnerabilities <tag>",
		Short:   packageVulnerabilitiesShort,
		Long:    packageVulnerabilitiesLong,
		Example: packageVulnerabilitiesExample,
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			opts.tag = args[0]
			if err := runPackageVulnerabilities(cmd, opts); err != nil {
				return fmt.Errorf("package vulnerabilities: %w", err)
			}
			return nil
		},
		ValidArgsFunction: completeLocalTags,
	}

	cmd.Flags().StringArrayVar(&opts.purls, "purl", nil, "only show the report for this purl (repeatable); shows every component's report if omitted")

	return cmd
}

func runPackageVulnerabilities(cmd *cobra.Command, opts *packageVulnerabilitiesOptions) error {
	logger := logging.FromContext(cmd.Context())

	sbomHash, err := build.ResolveTag(dataDir, opts.tag)
	if err != nil {
		return err
	}

	bom, err := sbom.Load(build.ManifestPath(dataDir, sbomHash))
	if err != nil {
		return fmt.Errorf("load sbom: %w", err)
	}

	var components []cdx.Component
	if bom.Components != nil {
		components = *bom.Components
	}

	wantPurls := make(map[string]bool, len(opts.purls))
	for _, purl := range opts.purls {
		wantPurls[purl] = true
	}
	matchedPurls := make(map[string]bool, len(wantPurls))

	printed := map[string]bool{}
	var reports [][]byte
	for _, component := range components {
		if len(wantPurls) > 0 && !wantPurls[component.PackageURL] {
			continue
		}
		matchedPurls[component.PackageURL] = true

		purlHash := plugin.PurlHash(component)
		if printed[purlHash] {
			continue
		}
		printed[purlHash] = true

		data, err := os.ReadFile(security.ReportPath(dataDir, purlHash))
		if err != nil {
			if os.IsNotExist(err) {
				logger.Debug("no vulnerability report", "purl", component.PackageURL)
				continue
			}
			return fmt.Errorf("read vulnerability report for %s: %w", component.PackageURL, err)
		}
		reports = append(reports, bytes.TrimSpace(data))
	}

	for purl := range wantPurls {
		if !matchedPurls[purl] {
			logger.Warn("--purl not found in this package's sbom", "purl", purl)
		}
	}

	if err := writeReportList(cmd.OutOrStdout(), reports); err != nil {
		return err
	}

	return nil
}

// writeReportList writes reports — each one component's vulnerability
// report, read straight off disk — to w as a single JSON array, so the
// whole of stdout is one value "jq" can parse directly, rather than the
// bare concatenation of documents that would result from writing each
// one to stdout in turn. Each report is decoded as a json.RawMessage
// (so its own field values are never re-parsed or reordered) and the
// whole array re-indented from scratch: the root brackets land at
// column 0, and everything else — each report's own braces included —
// nests two spaces per level under it, regardless of how it was
// formatted on disk.
func writeReportList(w io.Writer, reports [][]byte) error {
	raw := make([]json.RawMessage, len(reports))
	for i, report := range reports {
		raw[i] = report
	}

	data, err := json.Marshal(raw)
	if err != nil {
		return fmt.Errorf("marshal vulnerability report list: %w", err)
	}

	var buf bytes.Buffer
	if err := json.Indent(&buf, data, "", "  "); err != nil {
		return fmt.Errorf("indent vulnerability report list: %w", err)
	}
	buf.WriteByte('\n')

	_, err = w.Write(buf.Bytes())
	return err
}
