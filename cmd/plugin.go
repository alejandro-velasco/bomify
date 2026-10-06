package cmd

import (
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"strings"

	"github.com/spf13/cobra"
	"oras.land/oras-go/v2/registry"

	"github.com/alejandro-velasco/bomify/internal/layout"
	"github.com/alejandro-velasco/bomify/internal/logging"
	"github.com/alejandro-velasco/bomify/internal/oci/transfer"
	"github.com/alejandro-velasco/bomify/internal/plugin"
	"github.com/alejandro-velasco/bomify/internal/plugin/install"
	"github.com/alejandro-velasco/bomify/internal/prefix"
	"github.com/alejandro-velasco/bomify/internal/signature"
	"github.com/alejandro-velasco/bomify/internal/table"
	pluginlib "github.com/alejandro-velasco/bomify/pkg/plugin"
)

// defaultPluginRegistry is where "bomify plugin install" looks for plugin
// packages unless --registry says otherwise: <registry>/<name>:<version>.
const defaultPluginRegistry = "ghcr.io/alejandro-velasco/bomify/plugins"

// pluginVerifier is the signing plugin "bomify plugin install" verifies
// signatures with, when it's installed and has a key to verify against.
const pluginVerifier = "sigstore"

const pluginShort = "Install and list bomify plugins"

func pluginCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "plugin",
		Short: pluginShort,
	}

	cmd.AddCommand(pluginInstallCmd())
	cmd.AddCommand(pluginListCmd())

	return cmd
}

const pluginInstallShort = "Install a plugin from an OCI registry"

const pluginInstallLong = `Install downloads the plugin package "<registry>/<name>[:<version>]"
("latest" by default; "<name>@sha256:..." pins a digest) and installs
the binary built for this machine into <data-dir>/plugins as
bomify-plugin-<name>, replacing any earlier install.

A plugin is installed only if something vouches for it, checked before
downloading:
  - its signature, verified by bomify-plugin-sigstore against
    --verify-option (e.g. key=<public key>, or certificate-identity
    and certificate-oidc-issuer) or else the matching "bomify trust"
    rule; or
  - a digest pin, which is how bomify-plugin-sigstore itself is
    installed first, from the digests each release publishes.

Each binary must also match the SHA-256 its SBOM declares, and speak the
plugin contract versions bomify does, as its SBOM records. --verify=false
skips the signature requirement, but not these checks.`

const pluginInstallExample = `  # Bootstrap: install bomify-plugin-sigstore pinned to the digest a
  # bomify release published for it
  bomify plugin install sigstore@sha256:<digest>

  # Install the latest bomify-plugin-oci (needs a signer configured, e.g.
  # a "bomify trust" rule for its registry)
  bomify plugin install oci

  # Install a specific version
  bomify plugin install grype:1.12.0

  # Install from another registry, verifying its signature with a cosign key
  bomify plugin install myplugin --registry registry.example.com/plugins --verify-option key=cosign.pub

  # Install without verifying anything beyond the pull's own digest checks
  bomify plugin install oci --verify=false`

type pluginInstallOptions struct {
	registry      string
	verify        bool
	verifyOptions []string
	concurrency   int
}

func pluginInstallCmd() *cobra.Command {
	opts := &pluginInstallOptions{}

	cmd := &cobra.Command{
		Use:     "install <name>[:<version>|@<digest>]",
		Short:   pluginInstallShort,
		Long:    pluginInstallLong,
		Example: pluginInstallExample,
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := runPluginInstall(cmd, args[0], opts); err != nil {
				return fmt.Errorf("plugin install: %w", err)
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&opts.registry, "registry", defaultPluginRegistry, "repository prefix plugin packages are pulled from, as <registry>/<name>:<version>")
	cmd.Flags().BoolVar(&opts.verify, "verify", true, "verify plugin binaries' checksums and, when possible, the package's signature")
	cmd.Flags().StringArrayVar(&opts.verifyOptions, "verify-option", nil, "a key=value option passed to bomify-plugin-sigstore to verify the package's signature (repeatable; e.g. key=cosign.pub)")
	cmd.Flags().IntVarP(&opts.concurrency, "concurrency", "c", 3, "number of layers to download concurrently")

	return cmd
}

func runPluginInstall(cmd *cobra.Command, name string, opts *pluginInstallOptions) error {
	logger := logging.FromContext(cmd.Context())

	ref, err := pluginReference(opts.registry, name)
	if err != nil {
		return err
	}

	verifier, err := pluginInstallVerifier(ref, opts, logger)
	if err != nil {
		return err
	}

	repo, err := newRepository(ref)
	if err != nil {
		return err
	}

	mb := newMultiBar(cmd.OutOrStderr())
	restoreLogs := logging.SetOutput(mb)
	records, err := install.Install(cmd.Context(), repo, ref, dataDir, install.Options{
		Concurrency:     opts.concurrency,
		Progress:        newProgressFunc(mb),
		Verify:          verifier,
		RequireChecksum: opts.verify,
		Logger:          logger,
	})
	mb.Wait()
	restoreLogs()
	if err != nil {
		return err
	}

	for _, record := range records {
		fmt.Fprintf(cmd.OutOrStdout(), "Installed %s %s from %s\n", plugin.BinaryName(record.Kind), dashIfEmpty(record.Version), record.Reference)
	}
	return nil
}

// pluginNamePattern is what a plugin name must look like: a single OCI
// repository path component.
var pluginNamePattern = regexp.MustCompile(`^[a-z0-9]+(?:[._-][a-z0-9]+)*$`)

// pluginReference turns "<name>[:<version>|@<digest>]" into the package
// reference "<registry>/<name>:<version>" (version defaulting to
// "latest"), or "<registry>/<name>@<digest>".
func pluginReference(registry, name string) (string, error) {
	registry = strings.TrimSuffix(registry, "/")
	if registry == "" {
		return "", fmt.Errorf("--registry must not be empty")
	}

	suffix := ":latest"
	if base, digest, ok := strings.Cut(name, "@"); ok {
		name, suffix = base, "@"+digest
	} else if base, version, ok := strings.Cut(name, ":"); ok {
		name, suffix = base, ":"+version
	}

	if !pluginNamePattern.MatchString(name) {
		return "", fmt.Errorf("invalid plugin name %q: want lowercase letters, digits, and '.', '_', '-' separators (e.g. \"oci\")", name)
	}
	if suffix == ":" || suffix == "@" {
		return "", fmt.Errorf("invalid plugin reference %q: empty version or digest", name+suffix)
	}

	return registry + "/" + name + suffix, nil
}

// pluginInstallVerifier returns the verifier enforcing
// pluginInstallPolicy's decision for ref, or nil when ref's signature
// isn't verified.
func pluginInstallVerifier(ref string, opts *pluginInstallOptions, logger *slog.Logger) (transfer.Verifier, error) {
	policy, err := pluginInstallPolicy(ref, opts, logger)
	if err != nil || policy == nil {
		return nil, err
	}
	return signature.NewVerifier(layout.Plugins(dataDir), *policy, logger), nil
}

// pluginInstallPolicy decides how ref's signature is verified (see
// pluginInstallLong), returning nil when it isn't.
func pluginInstallPolicy(ref string, opts *pluginInstallOptions, logger *slog.Logger) (*signature.Policy, error) {
	if err := validateOptions("--verify-option", opts.verifyOptions); err != nil {
		return nil, err
	}
	if !opts.verify {
		if len(opts.verifyOptions) > 0 {
			return nil, fmt.Errorf("--verify-option given with --verify=false")
		}
		logger.Warn("skipping plugin verification", "reference", ref)
		return nil, nil
	}

	_, err := plugin.Find(layout.Plugins(dataDir), pluginVerifier, pluginlib.SigningContract)
	verifierInstalled := err == nil

	switch {
	case err == nil, errors.Is(err, plugin.ErrNotInstalled):
	case errors.Is(err, plugin.ErrIncompatible):
		// A verifier too old (or new) to speak the signing contract
		// bomify needs can only be replaced by a package that's safe
		// without it: one pinned by digest.
		if len(opts.verifyOptions) > 0 || !isDigestReference(ref) {
			return nil, fmt.Errorf("can't verify %s: %w — install a current %s pinned by digest first (%s@sha256:<digest>, digests are published with each bomify release)", ref, err, plugin.BinaryName(pluginVerifier), pluginVerifier)
		}
		logger.Warn("installing by pinned digest, without a signature check: the installed verifier is incompatible", "reference", ref, "error", err)
		return nil, nil
	default:
		return nil, err
	}

	if len(opts.verifyOptions) > 0 {
		if !verifierInstalled {
			return nil, fmt.Errorf("--verify-option needs %s, which isn't installed: %w", plugin.BinaryName(pluginVerifier), err)
		}
		return &signature.Policy{Verifier: signature.Plugin{Kind: pluginVerifier, Options: opts.verifyOptions}}, nil
	}

	rules, err := signature.ReadResolved(dataDir)
	if err != nil {
		return nil, err
	}
	if rule, ok := signature.Resolve(rules, ref); ok {
		logger.Debug("verifying plugin package per trust rule", "reference", ref, "match", rule.Match, "signers", len(rule.Signers))
		return &signature.Policy{Rules: rules}, nil
	}

	// No signer to check against. A reference pinned by digest is still
	// safe to install: the pull verifies every blob against that digest,
	// so the caller — who got it from somewhere they trust, e.g. a release
	// page — has named exactly what they'll get. Anything else would be
	// installing unauthenticated code, so it's refused.
	if isDigestReference(ref) {
		logger.Info("installing by pinned digest, without a signature check", "reference", ref)
		return nil, nil
	}

	if !verifierInstalled {
		return nil, fmt.Errorf("can't verify %s: %s isn't installed, and nothing else vouches for it — install it pinned by digest first (%s@sha256:<digest>, digests are published with each bomify release), pin this package by digest, or pass --verify=false to install it unverified", ref, plugin.BinaryName(pluginVerifier), pluginVerifier)
	}
	return nil, fmt.Errorf("can't verify %s: no signer is configured for it — pass --verify-option (key=<public key>, or certificate-identity=... and certificate-oidc-issuer=... for a keyless signer), run \"bomify trust create %s --match %s --option ...\" with the same options, pin it by digest, or pass --verify=false to install it unverified", ref, pluginVerifier, prefix.Repository(ref))
}

// isDigestReference reports whether ref names its package by a valid
// digest ("...@sha256:<hex>"), rather than by a tag that could be moved.
func isDigestReference(ref string) bool {
	r, err := registry.ParseReference(ref)
	return err == nil && r.ValidateReferenceAsDigest() == nil
}

const pluginListShort = "List installed plugins"

const pluginListLong = `List prints every plugin in <data-dir>/plugins, with the version and
package "bomify plugin install" installed it from, or "-" for one placed
there another way.`

const pluginListExample = `  # See every installed plugin
  bomify plugin list`

func pluginListCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "list",
		Short:   pluginListShort,
		Long:    pluginListLong,
		Example: pluginListExample,
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := runPluginList(cmd); err != nil {
				return fmt.Errorf("plugin list: %w", err)
			}
			return nil
		},
	}

	return cmd
}

func runPluginList(cmd *cobra.Command) error {
	entries, err := install.List(dataDir)
	if err != nil {
		return err
	}

	rows := make([][]string, 0, len(entries))
	for _, entry := range entries {
		version, source := "-", "-"
		if entry.Record != nil {
			version, source = dashIfEmpty(entry.Record.Version), entry.Record.Reference
		}
		rows = append(rows, []string{entry.Kind, version, source})
	}
	return table.Write(cmd.OutOrStdout(), []string{"NAME", "VERSION", "SOURCE"}, rows)
}

// dashIfEmpty returns s, or "-" if it's empty.
func dashIfEmpty(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
