package cmd

import (
	"errors"
	"fmt"
	"io"

	"github.com/package-url/packageurl-go"
	"github.com/spf13/cobra"
	"github.com/vbauerster/mpb/v8/decor"

	"github.com/alejandro-velasco/bomify/internal/layout"
	"github.com/alejandro-velasco/bomify/internal/oci/pull"
	"github.com/alejandro-velasco/bomify/internal/signature"
	"github.com/alejandro-velasco/bomify/internal/table"
)

const componentShort = "List and pull the components of a package in an OCI registry"

const componentLong = `A package's components are the ones its SBOM describes: each a model, an
image, a chart, or a set of files. These commands work on one package in
a registry without pulling the rest of it.`

func componentCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "component",
		Short: componentShort,
		Long:  componentLong,
	}

	cmd.AddCommand(componentListCmd())
	cmd.AddCommand(componentPullCmd())

	return cmd
}

const componentListShort = "List the components of a package in an OCI registry"

const componentListLong = `List prints each component of the package <reference>: its name and
version, which "bomify component pull" takes to name it, its purl type,
the size of its files, and the reference "bomify push" tagged it under,
which tools such as docker, helm, and oras pull it from.

It reads only the package's index, SBOM, and files map, without
downloading a component or touching the data directory, and verifies
nothing: "bomify component pull" does.`

const componentListExample = `  # List what a package holds
  bomify component list registry.example.com/llm-serving:1.0

  # List a package by digest
  bomify component list registry.example.com/llm-serving@sha256:abcdef...`

func componentListCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "list <reference>",
		Short:   componentListShort,
		Long:    componentListLong,
		Example: componentListExample,
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := runComponentList(cmd, args[0]); err != nil {
				return fmt.Errorf("component list: %w", err)
			}
			return nil
		},
	}

	return cmd
}

func runComponentList(cmd *cobra.Command, ref string) error {
	repo, err := newRepository(ref)
	if err != nil {
		return err
	}

	components, err := pull.Components(cmd.Context(), repo, ref)
	if err != nil {
		return err
	}
	return writeComponentTable(cmd.OutOrStdout(), components)
}

// writeComponentTable prints components, one row each: the name, version,
// purl type, size of its files, and reference. The purl itself, often long, is
// left out: the name selects a component, and an ambiguous one's error
// lists the purls that share it.
func writeComponentTable(w io.Writer, components []pull.PackageComponent) error {
	header := []string{"NAME", "VERSION", "TYPE", "SIZE", "REFERENCE"}
	rows := make([][]string, 0, len(components))
	for _, listed := range components {
		size := "-"
		if len(listed.Files.Files) > 0 {
			size = fmt.Sprintf("%.1f", decor.SizeB1024(listed.Files.Size()))
		}
		version := "-"
		if listed.Component.Version != "" {
			version = listed.Component.Version
		}
		purlType := "-"
		if purl, err := packageurl.FromString(listed.Component.PackageURL); err == nil {
			purlType = purl.Type
		}
		reference := "-"
		if listed.Reference != "" {
			reference = listed.Reference
		}
		row := []string{listed.Component.Name, version, purlType, size, reference}
		rows = append(rows, row)
	}
	table.RightAlign(3, header, rows)
	return table.Write(w, header, rows)
}

const componentPullShort = "Pull one component of a package from an OCI registry into a directory"

const componentPullLong = `Pull downloads only the files of the component <component> of the package
<reference> into --output, as they were when the package was built: for a
model, the directory a server loads it from; for an image, its OCI image
layout. --output must be missing or empty, which a volume mounted in a
container is, unless --replace is given: then what it holds is replaced,
once the component has downloaded and verified. A failed pull leaves
--output as it was, so a failed update keeps the old files. Nothing else
is written, and the package is not recorded in the data directory.

<component> is the component's purl, as "bomify component list" prints
it, or its name, alone or as <name>@<version>, when only one component
has it.

--verify requires a signature the named plugin verifies; without it, a
matching "bomify trust" rule applies. The package is verified before
anything is downloaded. --verify-provenance also requires the package's
build provenance, and --insecure-skip-verify bypasses a trust rule. See
"bomify pull" for how they work. Scanning is only available there.

--quiet prints only the package's pinned reference,
<repository>@<digest>, with no progress or info logging.`

const componentPullExample = `  # See what a package holds, then pull one model into a directory
  bomify component list registry.example.com/llm-serving:1.0
  bomify component pull registry.example.com/llm-serving:1.0 \
      pkg:huggingface/org/model@2db69c1c3e91a05d2c64a3185acfbaf36f744e25 \
      --output /models/model

  # By name, when only one component has it
  bomify component pull registry.example.com/llm-serving:1.0 model --output /models/model

  # Update a directory pulled before to the package's newer version
  bomify component pull registry.example.com/llm-serving:1.1 model --output /models/model --replace

  # Require a signature made with a specific cosign key
  bomify component pull registry.example.com/llm-serving:1.0 model --output /models/model \
      --verify sigstore --verify-option key=cosign.pub`

type componentPullOptions struct {
	transferFlags
	verify  verifyFlags
	output  string
	replace bool
}

func componentPullCmd() *cobra.Command {
	opts := &componentPullOptions{}

	cmd := &cobra.Command{
		Use:     "pull <reference> <component>",
		Short:   componentPullShort,
		Long:    componentPullLong,
		Example: componentPullExample,
		Args:    cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := runComponentPull(cmd, args[0], args[1], opts); err != nil {
				return fmt.Errorf("component pull: %w", err)
			}
			return nil
		},
	}

	opts.transferFlags.register(cmd, "download", "print only the package's pinned reference (<repository>@<digest>), with no progress or informational logging")
	opts.verify.register(cmd)
	cmd.Flags().StringVarP(&opts.output, "output", "o", "", "directory to write the component's files into (must be missing or empty, unless --replace)")
	cmd.Flags().BoolVar(&opts.replace, "replace", false, "replace what --output holds, once the component has downloaded and verified")
	cmd.MarkFlagRequired("output")

	return cmd
}

func runComponentPull(cmd *cobra.Command, ref, component string, opts *componentPullOptions) error {
	logger := opts.logger(cmd)

	policy, err := opts.verify.policy(dataDir)
	if err != nil {
		return err
	}
	transferOptions, done := opts.transferOptions(cmd)
	transferOptions.Verify = signature.NewVerifier(layout.Plugins(dataDir), policy, logger)
	transferOptions.VerifyProvenance = signature.NewProvenanceVerifier(layout.Plugins(dataDir), policy, logger)

	repo, err := newRepository(ref)
	if err != nil {
		done()
		return err
	}
	into := pull.ComponentOptions{
		Dir:     opts.output,
		Replace: opts.replace,
	}
	result, err := pull.PullComponent(cmd.Context(), repo, ref, component, into, transferOptions)
	done()
	if errors.Is(err, pull.ErrNoComponent) {
		return fmt.Errorf("%w (\"bomify component list %s\" lists them)", err, ref)
	}
	if err != nil {
		return err
	}

	logger.Info("component restored", "purl", result.Component.PackageURL, "path", result.Dir, "files", result.Files)
	opts.printPinned(cmd, ref, result.ManifestDigest)
	return nil
}
