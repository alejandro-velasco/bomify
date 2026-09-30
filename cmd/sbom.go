package cmd

import (
	"fmt"
	"os/exec"

	"github.com/spf13/cobra"

	"github.com/alejandro-velasco/bomify/internal/layout"
	"github.com/alejandro-velasco/bomify/internal/plugin"
)

const sbomShort = "Generate SBOMs for a deployment medium"

func sbomCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "sbom",
		Short: sbomShort,
	}

	cmd.AddCommand(sbomGenerateCmd())

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
// imposes any flags of its own here — see plugins/SBOM-CONTRACT.md.
func runSBOMGenerate(cmd *cobra.Command, medium string, args []string) error {
	path, err := plugin.Find(layout.Plugins(dataDir), medium)
	if err != nil {
		return err
	}

	sub := exec.Command(path, append([]string{"sbom", "generate"}, args...)...)
	sub.Stdin = cmd.InOrStdin()
	sub.Stdout = cmd.OutOrStdout()
	sub.Stderr = cmd.ErrOrStderr()

	return sub.Run()
}
