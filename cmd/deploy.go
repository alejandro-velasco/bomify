package cmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
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
	"github.com/alejandro-velasco/bomify/internal/table"
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

	cmd.AddCommand(deployListCmd())
	cmd.AddCommand(deployGenerateCmd())

	return cmd
}

const deployListShort = "List the deployments of a package in an OCI registry"

const deployListLong = `List reads the package <reference> from its registry, verified as
"bomify pull" would, and prints each of its deployments, as "bomify
build --deployments" packaged them, one row each: its name, its type,
whose plugin generates it, its options, its config and overlays, and the
deployments to apply before it, its templates named by their paths in
the package. A disabled one is marked so. These are the names a
deployment file given to "bomify deploy generate --file" overrides.
Nothing is written.`

const deployListExample = `  # See how a package deploys
  bomify deploy list registry.example.com/team/app:1.0`

type deployListOptions struct {
	verify verifyFlags
}

func deployListCmd() *cobra.Command {
	opts := &deployListOptions{}

	cmd := &cobra.Command{
		Use:     "list <reference>",
		Short:   deployListShort,
		Long:    deployListLong,
		Example: deployListExample,
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := runDeployList(cmd, args[0], opts); err != nil {
				return fmt.Errorf("deploy list: %w", err)
			}
			return nil
		},
	}

	opts.verify.register(cmd)

	return cmd
}

func runDeployList(cmd *cobra.Command, ref string, opts *deployListOptions) error {
	read, err := readDeployments(cmd, ref, opts.verify, "")
	if err != nil {
		return err
	}
	defer read.close()
	return writeDeploymentTable(cmd.OutOrStdout(), read.file, read.dir)
}

// writeDeploymentTable prints file's deployments as a table, one row
// each, naming each template by its path in packaged, the package's
// deployments.
func writeDeploymentTable(w io.Writer, file deploy.File, packaged string) error {
	header := []string{"NAME", "TYPE", "OPTIONS", "CONFIG", "OVERLAYS", "DEPENDS ON"}
	rows := make([][]string, 0, len(file.Deployments))
	for _, deployment := range file.Deployments {
		name := deployment.Name
		if deployment.Enabled != nil && !*deployment.Enabled {
			name += " (disabled)"
		}
		overlays := make([]string, 0, len(deployment.Overlays))
		for _, overlay := range deployment.Overlays {
			overlays = append(overlays, displayPath(overlay, packaged))
		}
		row := []string{
			name,
			deployment.Type,
			dashIfEmpty(strings.Join(deployOptions(deployment.Options), ", ")),
			dashIfEmpty(displayPath(deployment.Config, packaged)),
			dashIfEmpty(strings.Join(overlays, ", ")),
			dashIfEmpty(strings.Join(deployment.DependsOn, ", ")),
		}
		rows = append(rows, row)
	}
	return table.Write(w, header, rows)
}

// deployOptions is options as sorted "key=value"s.
func deployOptions(options map[string]*deploy.Option) []string {
	listed := make([]string, 0, len(options))
	for key, value := range options {
		if value != nil {
			listed = append(listed, key+"="+string(*value))
		}
	}
	sort.Strings(listed)
	return listed
}

// displayPath is path, one of the package's templates, by its path in
// packaged, as the package names it.
func displayPath(path, packaged string) string {
	if path == "" {
		return ""
	}
	if relative, err := filepath.Rel(packaged, path); err == nil && filepath.IsLocal(relative) {
		return filepath.ToSlash(relative)
	}
	return path
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

	if err := pull.CheckOutputDir(opts.output, opts.replace); err != nil {
		return err
	}
	read, err := readDeployments(cmd, ref, opts.verify, opts.file)
	if errors.Is(err, errNoDeployments) {
		return fmt.Errorf("%w: give them with --file", err)
	}
	if err != nil {
		return err
	}
	// The package's templates must stay until every deployment generates.
	defer read.close()
	description, err := deploy.Describe(cmd.Context(), ref, read.pkg.Digest, read.pkg.Components, resolveTag)
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
	index, err := deploy.Generate(description, read.file, generateOptions)
	if err != nil {
		return err
	}
	writeGenerated(cmd.OutOrStdout(), index)
	return nil
}

// packageDeployments is a package in a registry, verified, and the
// deployments to generate for it.
type packageDeployments struct {
	pkg  pull.VerifiedPackage
	file deploy.File
	// dir holds the package's deployment files, which file names, until
	// close removes it.
	dir string
}

func (p *packageDeployments) close() { os.RemoveAll(p.dir) }

// readDeployments reads ref's package from its registry, verified as
// verify and the data directory's trust rules ask, and its deployments,
// with the deployment file at userPath, if any, laid over them. The file
// is read first, so a bad one fails before the registry is read; it's
// checked whole once laid over the package's, which may complete it. Call
// close once done with them.
func readDeployments(cmd *cobra.Command, ref string, verify verifyFlags, userPath string) (*packageDeployments, error) {
	var userFile *deploy.File
	if userPath != "" {
		loaded, err := deploy.Load(userPath)
		if err != nil {
			return nil, err
		}
		userFile = &loaded
	}

	logger := logging.FromContext(cmd.Context())
	policy, err := verify.policy(dataDir)
	if err != nil {
		return nil, err
	}
	verifyOptions := transfer.Options{
		Verify:           signature.NewVerifier(layout.Plugins(dataDir), policy, logger),
		VerifyProvenance: signature.NewProvenanceVerifier(layout.Plugins(dataDir), policy, logger),
	}
	repo, err := newRepository(ref)
	if err != nil {
		return nil, err
	}
	pkg, err := pull.FetchVerified(cmd.Context(), repo, ref, verifyOptions)
	if err != nil {
		return nil, err
	}

	dir, err := os.MkdirTemp("", "bomify-deployments-*")
	if err != nil {
		return nil, err
	}
	file, err := deployments(cmd.Context(), repo, pkg, dir, userFile)
	if err != nil {
		os.RemoveAll(dir)
		return nil, err
	}
	read := packageDeployments{
		pkg:  pkg,
		file: file,
		dir:  dir,
	}
	return &read, nil
}

// errNoDeployments is what deployments returns for a package without
// deployments, given none of the user's.
var errNoDeployments = errors.New("the package has no deployments")

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
		return deploy.File{}, errNoDeployments
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
