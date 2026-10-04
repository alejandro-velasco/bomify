package cmd

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/spf13/cobra"

	"github.com/alejandro-velasco/bomify/internal/layout"
	"github.com/alejandro-velasco/bomify/internal/logging"
	"github.com/alejandro-velasco/bomify/internal/plugin"
	"github.com/alejandro-velasco/bomify/internal/sbom"
	pluginlib "github.com/alejandro-velasco/bomify/pkg/plugin"
)

const sbomShort = "Generate and compose SBOMs for deployment mediums"

func sbomCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "sbom",
		Short: sbomShort,
	}

	cmd.AddCommand(sbomGenerateCmd())
	cmd.AddCommand(sbomComposeCmd())

	return cmd
}

const sbomGenerateShort = "Generate an SBOM for a deployment medium via its plugin"

const sbomGenerateLong = `Generate runs "bomify-plugin-<medium> sbom generate" with every flag
after <medium> passed through unchanged and stdin, stdout, and stderr
wired straight through; running the plugin directly is equivalent. See
the plugin's --help for its flags. bomify's own flags, such as
--data-dir, must come before <medium>.`

const sbomGenerateExample = `  # Generate an SBOM for a Helm chart
  bomify sbom generate helm --chart postgresql --repo oci://registry-1.docker.io/bitnamicharts --version 15.6.0 --values values.yaml`

func sbomGenerateCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "generate <medium> [flags]",
		Short:   sbomGenerateShort,
		Long:    sbomGenerateLong,
		Example: sbomGenerateExample,
		Args:    cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := runSBOMGenerate(cmd, args[0], args[1:]); err != nil {
				return fmt.Errorf("sbom generate: %w", err)
			}
			return nil
		},
	}

	// Every flag after <medium> belongs to the plugin, not bomify: stop
	// parsing flags at <medium>, so they (--help included) arrive in args
	// untouched, while bomify's own flags before it (e.g. --data-dir,
	// which decides where the plugin is found) are parsed as usual.
	cmd.Flags().SetInterspersed(false)

	return cmd
}

// runSBOMGenerate execs "bomify-plugin-<medium> sbom generate" with args
// passed through exactly as given, wiring cmd's own stdin/stdout/stderr
// straight to the plugin's. bomify neither parses the plugin's output nor
// imposes any flags of its own here — see
// plugins/contracts/sbom/v1/CONTRACT.md.
func runSBOMGenerate(cmd *cobra.Command, medium string, args []string) error {
	path, err := plugin.Find(layout.Plugins(dataDir), medium, pluginlib.SBOMContract)
	if err != nil {
		return err
	}

	sub := exec.Command(path, append([]string{pluginlib.SBOMSubcommand, "generate"}, args...)...)
	sub.Stdin = cmd.InOrStdin()
	sub.Stdout = cmd.OutOrStdout()
	sub.Stderr = cmd.ErrOrStderr()

	return sub.Run()
}

const sbomComposeShort = "Compose one SBOM from several deployment mediums"

const sbomComposeLong = `Compose merges the SBOMs a composition file lists into one, for
"bomify build" to build as one package. Each source is either a medium,
whose plugin generates an SBOM from the source's options, or an existing
CycloneDX file. The file's own "components" are added too.

Every source's options are checked against its plugin's "sbom schema"
before any plugin runs. Plugins run in the composition file's directory,
so relative paths in options resolve against it, as "sbom" paths do.
Each SBOM must follow the SBOM generation contract's output rules.

Components are merged by purl, each recording the sources it came from
in its "land.bomify.compose.sources" property; two sources disagreeing
on the same purl's type, name, version, or hashes is an error. The
result describes the composition itself, by its "name" and "version",
depending on each source's root. The same sources always compose the
same SBOM, so rebuilding it builds the same package.`

const sbomComposeExample = `  # Compose bomify.yaml and build the result
  bomify sbom compose bomify.yaml -o app.cdx.json
  bomify build app.cdx.json --tag myapp:1.4.0

  # bomify.yaml: two charts and a vendored SBOM
  name: myapp
  version: 1.4.0
  sources:
    - name: web
      medium: helm
      options: {chart: web, repo: "oci://registry.example.com/charts", version: 2.1.0, values: [values/web.yaml]}
    - name: db
      medium: helm
      options: {chart: postgresql, repo: "oci://registry-1.docker.io/bitnamicharts", version: 15.6.0}
    - name: tools
      sbom: vendor/tools.cdx.json`

func sbomComposeCmd() *cobra.Command {
	var output string

	cmd := &cobra.Command{
		Use:     "compose <file>",
		Short:   sbomComposeShort,
		Long:    sbomComposeLong,
		Example: sbomComposeExample,
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := runSBOMCompose(cmd, args[0], output, logging.FromContext(cmd.Context())); err != nil {
				return fmt.Errorf("sbom compose: %w", err)
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&output, "output", "o", "", "write the SBOM to this file instead of stdout")

	return cmd
}

func runSBOMCompose(cmd *cobra.Command, path, output string, logger *slog.Logger) error {
	c, err := sbom.LoadComposition(path)
	if err != nil {
		return err
	}

	// Find every plugin and check every source's options first, so a
	// mistake in the last source doesn't wait for the others to generate.
	plugins := map[string]string{}
	for _, s := range c.Sources {
		if s.Medium == "" {
			continue
		}
		bin, ok := plugins[s.Medium]
		if !ok {
			if bin, err = plugin.Find(layout.Plugins(dataDir), s.Medium, pluginlib.SBOMContract); err != nil {
				return fmt.Errorf("source %q: %w", s.Name, err)
			}
			plugins[s.Medium] = bin
		}
		schema, err := plugin.SBOMSchema(bin)
		if err != nil {
			return fmt.Errorf("source %q: %w", s.Name, err)
		}
		if err := plugin.ValidateOptions(schema, s.OptionsJSON()); err != nil {
			return fmt.Errorf("source %q: options: %w", s.Name, err)
		}
	}

	parts := make([]sbom.Part, 0, len(c.Sources))
	for _, s := range c.Sources {
		bom, err := sourceSBOM(c, s, plugins[s.Medium], cmd.ErrOrStderr(), logger)
		if err != nil {
			return fmt.Errorf("source %q: %w", s.Name, err)
		}
		parts = append(parts, sbom.Part{Source: s.Name, BOM: bom})
	}

	bom, err := c.Merge(parts)
	if err != nil {
		return err
	}
	logger.Info("composed sbom", "name", c.Name, "version", c.Version, "sources", len(parts), "components", len(sbom.Components(bom.Components)))

	if output == "" {
		return sbom.Write(cmd.OutOrStdout(), bom)
	}
	f, err := os.Create(output)
	if err != nil {
		return fmt.Errorf("create %s: %w", output, err)
	}
	if err := sbom.Write(f, bom); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// sourceSBOM returns s's SBOM: read from its file, or generated by the
// plugin at bin, which logs to logs.
func sourceSBOM(c *sbom.Composition, s sbom.Source, bin string, logs io.Writer, logger *slog.Logger) (*cdx.BOM, error) {
	if s.SBOM != "" {
		logger.Info("reading sbom", "source", s.Name, "path", s.SBOM)
		return sbom.Load(c.Path(s.SBOM))
	}

	config, err := os.CreateTemp("", "bomify-sbom-options-*.json")
	if err != nil {
		return nil, fmt.Errorf("create options file: %w", err)
	}
	defer os.Remove(config.Name())
	if _, err := config.Write(s.OptionsJSON()); err != nil {
		config.Close()
		return nil, fmt.Errorf("write options file: %w", err)
	}
	if err := config.Close(); err != nil {
		return nil, fmt.Errorf("write options file: %w", err)
	}

	logger.Info("generating sbom", "source", s.Name, "medium", s.Medium)
	return plugin.GenerateSBOM(bin, filepath.Clean(config.Name()), c.Dir(), logs)
}
