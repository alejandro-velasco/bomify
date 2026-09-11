package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"bomify/internal/sbom"
)

var (
	buildInput  string
	buildOutput string
)

var buildCmd = &cobra.Command{
	Use:   "build",
	Short: "Build packages described by a CycloneDX SBOM",
	Long:  "Build reads a CycloneDX SBOM and builds a package for each component it describes.",
	RunE:  runBuild,
}

func init() {
	buildCmd.Flags().StringVarP(&buildInput, "input", "i", "", "path to the CycloneDX SBOM file (JSON or XML)")
	buildCmd.Flags().StringVarP(&buildOutput, "output", "o", "dist", "directory to write built packages to")
	_ = buildCmd.MarkFlagRequired("input")

	rootCmd.AddCommand(buildCmd)
}

func runBuild(cmd *cobra.Command, args []string) error {
	bom, err := sbom.Load(buildInput)
	if err != nil {
		return fmt.Errorf("load sbom: %w", err)
	}

	name := "unknown"
	if bom.Metadata != nil && bom.Metadata.Component != nil {
		name = bom.Metadata.Component.Name
	}

	fmt.Printf("Loaded SBOM for %q with %d component(s)\n", name, sbom.ComponentCount(bom))
	fmt.Printf("Output directory: %s\n", buildOutput)

	// TODO: build a package for each component described in the SBOM.
	fmt.Println("build: package generation is not implemented yet")

	return nil
}
