package cmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/opencontainers/go-digest"
	"github.com/spf13/cobra"
	"oras.land/oras-go/v2/content"
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
deployed from, verifies it as "bomify pull" would, and runs each of its
deployments through its plugin, writing into --output: one directory per
deployment, named after it, and deployments.json, recording what each
wrote, what it depends on, and what to do with it. Nothing is deployed,
and nothing is written to the data directory.

The deployments are the package's own, as "bomify build --deployments"
recorded them, with --file laid over them deployment by deployment,
matched by name: a deployment of the same name changes the package's,
and a new name adds one. For one the package has, --file's options are
merged over the package's, a null removing one; its config replaces the
package's; its overlays are laid over the package's config; its
dependsOn replaces the package's; and "enabled: false" skips it. A
package without deployments needs --file.

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

const deployGenerateExample = `  # Generate a package's deployments
  bomify deploy generate registry.example.com/team/app:1.0 --output deploy/

  # Change them with deploy.yaml, or generate a package's without any
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
	cmd.Flags().StringVarP(&opts.file, "file", "f", "", "a deployment file to lay over the package's deployments, or to use instead of them if it has none")
	cmd.Flags().StringVarP(&opts.output, "output", "o", "", "directory to write into (must be missing or empty, unless --replace)")
	cmd.Flags().BoolVar(&opts.replace, "replace", false, "replace what --output holds, once every deployment has generated")
	cmd.MarkFlagRequired("output")

	return cmd
}

func runDeployGenerate(cmd *cobra.Command, ref string, opts *deployGenerateOptions) error {
	logger := logging.FromContext(cmd.Context())

	// Read before the registry is, so a bad file fails fast. It's checked
	// whole once laid over the package's, which may complete it.
	var userFile *deploy.File
	if opts.file != "" {
		loaded, err := deploy.Load(opts.file)
		if err != nil {
			return err
		}
		userFile = &loaded
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
	pkg, err := pull.FetchVerified(cmd.Context(), repo, ref, verify)
	if err != nil {
		return err
	}
	description, err := deploy.Describe(cmd.Context(), ref, pkg.Digest, pkg.Components, resolveTag)
	if err != nil {
		return err
	}

	// The package's templates must stay until every deployment generates.
	packaged, err := os.MkdirTemp("", "bomify-deployments-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(packaged)
	file, err := deployments(cmd.Context(), repo, pkg, packaged, userFile)
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

// deployments is what to generate for pkg, a package in target: its own
// deployments, fetched into dir, with user's laid over them, if user isn't
// nil; or user's alone, for a package without deployments.
func deployments(ctx context.Context, target content.Fetcher, pkg pull.VerifiedPackage, dir string, user *deploy.File) (deploy.File, error) {
	var file deploy.File
	if pkg.Deployments.Digest != "" {
		if err := transfer.FetchDeployments(ctx, target, pkg.Deployments, dir); err != nil {
			return deploy.File{}, err
		}
		packaged, err := deploy.LoadPackaged(dir)
		if err != nil {
			return deploy.File{}, err
		}
		file = packaged
	}
	if user != nil {
		laid, err := deploy.Lay(file, *user)
		if err != nil {
			return deploy.File{}, err
		}
		file = laid
	}
	if len(file.Deployments) == 0 {
		return deploy.File{}, errors.New("the package has no deployments: give them with --file")
	}
	return file, nil
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
