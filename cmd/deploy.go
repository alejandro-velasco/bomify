package cmd

import (
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/opencontainers/go-digest"
	"github.com/spf13/cobra"
	"oras.land/oras-go/v2/registry"

	"github.com/alejandro-velasco/bomify/internal/deploy"
	"github.com/alejandro-velasco/bomify/internal/layout"
	"github.com/alejandro-velasco/bomify/internal/logging"
	"github.com/alejandro-velasco/bomify/internal/oci/pull"
	"github.com/alejandro-velasco/bomify/internal/oci/transfer"
	"github.com/alejandro-velasco/bomify/internal/signature"
)

const deployShort = "Generate deployments of a package in an OCI registry"

const deployLong = `A package's deployments are what deployment tools deploy it with: Helm
values that pin every image to the package's copy by digest, say. Each
deployment medium has a plugin, bomify-plugin-<type>.`

func deployCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "deploy",
		Short: deployShort,
		Long:  deployLong,
	}

	cmd.AddCommand(deployGenerateCmd())

	return cmd
}

const deployGenerateShort = "Generate what deployment tools deploy, from a package in an OCI registry"

const deployGenerateLong = `Generate reads the package <reference> from the registry it will be
deployed from, verifies it as "bomify pull" would, and runs each
deployment in --file through its plugin, writing into --output: one
directory per deployment, named after it, and deployments.json,
recording what each wrote, what it depends on, and what to do with it.
Nothing is deployed, and nothing is written to the data directory.

Each component is pinned by digest in the package's repository, where
every copy of the package holds it, and its tag, where "bomify push"
tagged it, is passed on only if the registry has it: a package copied
another way, or pushed with --skip-component-repositories, has none. To
deploy from a mirror, name the package there.

--output must be missing or empty, unless --replace is given: then what
it holds is replaced, once every deployment has generated. A failed
deployment leaves --output as it was.

--verify, its options, and a matching "bomify trust" rule work as for
"bomify pull"; see there.`

const deployGenerateExample = `  # Generate the deployments in deploy.yaml for a package in a registry
  bomify deploy generate registry.example.com/team/app:1.0 --file deploy.yaml --output deploy/

  # Regenerate them over what was generated before
  bomify deploy generate registry.example.com/team/app:1.1 --file deploy.yaml --output deploy/ --replace`

type deployGenerateOptions struct {
	verify  verifyFlags
	file    string
	output  string
	replace bool
}

func deployGenerateCmd() *cobra.Command {
	opts := &deployGenerateOptions{}

	cmd := &cobra.Command{
		Use:     "generate <reference>",
		Short:   deployGenerateShort,
		Long:    deployGenerateLong,
		Example: deployGenerateExample,
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := runDeployGenerate(cmd, args[0], opts); err != nil {
				return fmt.Errorf("deploy generate: %w", err)
			}
			return nil
		},
	}

	opts.verify.register(cmd)
	cmd.Flags().StringVarP(&opts.file, "file", "f", "", "the deployment file: the deployments to generate (required)")
	cmd.Flags().StringVarP(&opts.output, "output", "o", "", "directory to write into (must be missing or empty, unless --replace)")
	cmd.Flags().BoolVar(&opts.replace, "replace", false, "replace what --output holds, once every deployment has generated")
	cmd.MarkFlagRequired("file")
	cmd.MarkFlagRequired("output")

	return cmd
}

func runDeployGenerate(cmd *cobra.Command, ref string, opts *deployGenerateOptions) error {
	logger := logging.FromContext(cmd.Context())

	file, err := deploy.Load(opts.file)
	if err != nil {
		return err
	}
	// Checked before the registry is read, so a bad file fails fast.
	if err := deploy.Check(file); err != nil {
		return err
	}
	if err := pull.CheckOutputDir(opts.output, opts.replace); err != nil {
		return err
	}

	policy, err := opts.verify.policy(dataDir)
	if err != nil {
		return err
	}
	verify := transfer.Options{
		Verify:           signature.NewVerifier(layout.Plugins(dataDir), policy, logger),
		VerifyProvenance: signature.NewProvenanceVerifier(layout.Plugins(dataDir), policy, logger),
	}
	repo, err := newRepository(ref)
	if err != nil {
		return err
	}
	packageDigest, components, err := pull.VerifiedComponents(cmd.Context(), repo, ref, verify)
	if err != nil {
		return err
	}
	description, err := deploy.Describe(cmd.Context(), ref, packageDigest, components, resolveTag)
	if err != nil {
		return err
	}

	generateOptions := deploy.GenerateOptions{
		Plugins: layout.Plugins(dataDir),
		DataDir: dataDir,
		Output:  opts.output,
		Replace: opts.replace,
		Logger:  logger,
	}
	index, err := deploy.Generate(description, file, generateOptions)
	if err != nil {
		return err
	}
	writeGenerated(cmd.OutOrStdout(), index)
	return nil
}

// resolveTag is a deploy.TagResolver against reference's registry.
func resolveTag(ctx context.Context, reference string) (digest.Digest, error) {
	parsed, err := registry.ParseReference(reference)
	if err != nil {
		return "", err
	}
	repo, err := newRepository(reference)
	if err != nil {
		return "", err
	}
	desc, err := repo.Resolve(ctx, parsed.Reference)
	if err != nil {
		return "", err
	}
	return desc.Digest, nil
}

// writeGenerated prints each deployment index records: its name and type,
// the files its plugin wrote, and what to do with them, from its
// directory.
func writeGenerated(w io.Writer, index deploy.Index) {
	for _, generated := range index.Deployments {
		fmt.Fprintf(w, "%s (%s): %s\n", generated.Name, generated.Type, strings.Join(generated.Files, ", "))
		if generated.Instructions != "" {
			fmt.Fprintf(w, "  in %s/: %s\n", generated.Name, generated.Instructions)
		}
	}
}
