package cmd

import (
	"fmt"
	"log/slog"
	"regexp"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/alejandro-velasco/bomify/internal/logging"
	"github.com/alejandro-velasco/bomify/internal/oci/transfer"
	"github.com/alejandro-velasco/bomify/internal/plugin"
	"github.com/alejandro-velasco/bomify/internal/plugin/install"
	"github.com/alejandro-velasco/bomify/internal/signature"
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

const pluginInstallLong = `Install downloads the plugin package "<registry>/<name>:<version>"
(version defaulting to "latest"; "<name>@sha256:..." pins a digest) and
installs the plugin binaries it carries into <data-dir>/plugins, the
only place bomify looks for plugins.

A plugin package is an ordinary bomify package whose SBOM describes
"pkg:bomify-plugin/<kind>" components, typically one per platform
(distinguished by "os"/"arch" purl qualifiers). Install walks those
components and installs, as bomify-plugin-<kind>, each one built for
this machine — replacing any earlier install of the same kind. The
package itself isn't kept as a local package the way "bomify pull"
would keep it.

By default (--verify), every plugin binary must match the SHA-256 its
component declares in the package's SBOM, on top of the digest checks
every pull performs. Once bomify-plugin-sigstore is installed, the
package's signature is verified too, against the signer named by the
first of:
  - --verify-option (e.g. key=<public key>, or certificate-identity and
    certificate-oidc-issuer for a keyless signature);
  - the most specific "bomify trust" rule matching the package.
Without either, only checksums are verified, with a warning — as for
bomify-plugin-sigstore itself, the first time it's installed.
--verify=false skips signature verification and no longer requires a
declared checksum (a declared one that doesn't match still fails).`

const pluginInstallExample = `  # Install the latest bomify-plugin-oci
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
	records, err := install.Install(cmd.Context(), repo, ref, dataDir, install.Options{
		Concurrency:     opts.concurrency,
		Progress:        newProgressFunc(mb),
		Verify:          verifier,
		RequireChecksum: opts.verify,
		Logger:          logger,
	})
	mb.Wait()
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
	return signature.NewVerifier(plugin.Dir(dataDir), *policy, logger), nil
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

	_, err := plugin.Find(plugin.Dir(dataDir), pluginVerifier)
	verifierInstalled := err == nil

	if len(opts.verifyOptions) > 0 {
		if !verifierInstalled {
			return nil, fmt.Errorf("--verify-option needs %s, which isn't installed: %w", plugin.BinaryName(pluginVerifier), err)
		}
		return &signature.Policy{Verifier: signature.Plugin{Kind: pluginVerifier, Options: opts.verifyOptions}}, nil
	}

	rules, err := signature.Read(dataDir)
	if err != nil {
		return nil, err
	}
	if rule, ok := signature.Resolve(rules, ref); ok {
		logger.Debug("verifying plugin package per trust rule", "reference", ref, "match", rule.Match, "verifier", rule.Verifier)
		return &signature.Policy{Rules: rules}, nil
	}

	if !verifierInstalled {
		logger.Warn(plugin.BinaryName(pluginVerifier)+" is not installed, verifying checksums only", "reference", ref)
		return nil, nil
	}

	hint := fmt.Sprintf("pass --verify-option (key=<public key>, or certificate-identity=... and certificate-oidc-issuer=... for a keyless signer), or run \"bomify trust create %s --match %s --option ...\" with the same options", pluginVerifier, signature.Repository(ref))
	logger.Warn("no signer configured for this plugin package, verifying checksums only", "reference", ref, "hint", hint)
	return nil, nil
}

const pluginListShort = "List installed plugins"

const pluginListLong = `List prints every plugin installed in <data-dir>/plugins. VERSION and
SOURCE show the version and package "bomify plugin install" installed
it from, or "-" for a binary placed there some other way (e.g. "make
install").`

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

	w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 3, ' ', 0)
	fmt.Fprintln(w, "NAME\tVERSION\tSOURCE")
	for _, entry := range entries {
		version, source := "-", "-"
		if entry.Record != nil {
			version, source = dashIfEmpty(entry.Record.Version), entry.Record.Reference
		}
		fmt.Fprintf(w, "%s\t%s\t%s\n", entry.Kind, version, source)
	}

	return w.Flush()
}

// dashIfEmpty returns s, or "-" if it's empty.
func dashIfEmpty(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
