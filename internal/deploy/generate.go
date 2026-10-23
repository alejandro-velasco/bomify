package deploy

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"sort"

	"github.com/alejandro-velasco/bomify/internal/fsutil"
	"github.com/alejandro-velasco/bomify/internal/oci/pull"
	"github.com/alejandro-velasco/bomify/internal/plugin"
	pluginlib "github.com/alejandro-velasco/bomify/pkg/plugin"
)

// IndexFile is the file Generate writes into its output, beside each
// deployment's directory, recording what it generated.
const IndexFile = "deployments.json"

// Index is IndexFile: what Generate generated, for whatever applies it.
type Index struct {
	// Package is the package, pinned: "<repository>@<digest>".
	Package     string      `json:"package"`
	Deployments []Generated `json:"deployments"`
}

// Generated is one deployment Generate generated.
type Generated struct {
	Name string `json:"name"`
	Type string `json:"type"`
	// Files are the files its plugin wrote, relative to the output, in
	// its directory.
	Files []string `json:"files"`
	// DependsOn names the deployments to apply before it.
	DependsOn []string `json:"dependsOn,omitempty"`
	// Instructions are what its plugin says to do with Files.
	Instructions string `json:"instructions,omitempty"`
}

// GenerateOptions are where Generate finds plugins and writes.
type GenerateOptions struct {
	// Plugins is the directory deployment plugins are installed in, and
	// DataDir the data directory their logs go in.
	Plugins string
	DataDir string
	// Output is the directory to write into: missing or empty, unless
	// Replace is set, when what it held is replaced.
	Output  string
	Replace bool
	Logger  *slog.Logger
}

// Generate runs each enabled deployment of file, in order, through its
// type's plugin, which writes into "<Output>/<name>", and records them all
// in IndexFile. Output only changes if every deployment succeeds.
func Generate(description pluginlib.DeploymentPackage, file File, opts GenerateOptions) (Index, error) {
	if err := Check(file); err != nil {
		return Index{}, err
	}
	var deployments []Deployment
	for _, deployment := range file.Deployments {
		if deployment.Enabled == nil || *deployment.Enabled {
			deployments = append(deployments, deployment)
		}
	}
	if len(deployments) == 0 {
		return Index{}, errors.New("no deployment to generate")
	}

	// Every plugin is found before any runs, so a missing one fails first.
	paths := map[string]string{}
	for _, deployment := range deployments {
		path, err := plugin.Find(opts.Plugins, deployment.Type, pluginlib.DeploymentContract)
		if err != nil {
			return Index{}, fmt.Errorf("deployment %q: %w", deployment.Name, err)
		}
		paths[deployment.Type] = path
	}

	descriptionFile, err := writeDescription(description)
	if err != nil {
		return Index{}, err
	}
	defer os.Remove(descriptionFile)

	index := Index{Package: description.Repository + "@" + description.Digest}
	write := func(stageDir string) error {
		for _, deployment := range deployments {
			generated, err := generateOne(deployment, paths[deployment.Type], descriptionFile, stageDir, opts)
			if err != nil {
				return fmt.Errorf("deployment %q: %w", deployment.Name, err)
			}
			index.Deployments = append(index.Deployments, generated)
		}
		return fsutil.WriteJSON(filepath.Join(stageDir, IndexFile), index)
	}
	if err := pull.WriteInto(opts.Output, opts.Replace, write); err != nil {
		return Index{}, err
	}
	return index, nil
}

// generateOne runs deployment's plugin, at path, into its directory of
// stageDir, and checks it wrote what it reports.
func generateOne(deployment Deployment, path, descriptionFile, stageDir string, opts GenerateOptions) (Generated, error) {
	dir := filepath.Join(stageDir, deployment.Name)
	if err := os.Mkdir(dir, 0o755); err != nil {
		return Generated{}, err
	}
	call := plugin.Deployment{
		Name:     deployment.Name,
		Package:  descriptionFile,
		Output:   dir,
		Config:   deployment.Config,
		Overlays: deployment.Overlays,
		Options:  optionArgs(deployment.Options),
	}
	result, err := plugin.Generate(path, call, opts.DataDir, opts.Logger)
	if err != nil {
		return Generated{}, err
	}
	if err := checkWrote(dir, result.Files); err != nil {
		return Generated{}, err
	}

	files := make([]string, 0, len(result.Files))
	for _, written := range result.Files {
		files = append(files, deployment.Name+"/"+written)
	}
	generated := Generated{
		Name:         deployment.Name,
		Type:         deployment.Type,
		Files:        files,
		DependsOn:    deployment.DependsOn,
		Instructions: result.Instructions,
	}
	return generated, nil
}

// optionArgs is options as "key=value" arguments, sorted, so a plugin is
// called the same way every time.
func optionArgs(options map[string]*Option) []string {
	args := make([]string, 0, len(options))
	for key, value := range options {
		if value != nil {
			args = append(args, key+"="+string(*value))
		}
	}
	sort.Strings(args)
	return args
}

// writeDescription writes description to a temporary file, returning its
// path, for the caller to remove.
func writeDescription(description pluginlib.DeploymentPackage) (string, error) {
	file, err := os.CreateTemp("", "bomify-package-*.json")
	if err != nil {
		return "", fmt.Errorf("write package description: %w", err)
	}
	path := file.Name()
	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	err = errors.Join(encoder.Encode(description), file.Close())
	if err != nil {
		os.Remove(path)
		return "", fmt.Errorf("write package description: %w", err)
	}
	return path, nil
}

// checkWrote fails unless dir holds exactly the files listed, "/"-separated
// paths relative to it, all regular files, and at least one.
func checkWrote(dir string, listed []string) error {
	if len(listed) == 0 {
		return errors.New("the plugin reported writing no files")
	}
	var wrote []string
	err := filepath.WalkDir(dir, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		relative, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}
		relative = filepath.ToSlash(relative)
		if !entry.Type().IsRegular() {
			return fmt.Errorf("the plugin wrote %s, which isn't a regular file", relative)
		}
		wrote = append(wrote, relative)
		return nil
	})
	if err != nil {
		return err
	}
	for _, path := range listed {
		if !slices.Contains(wrote, path) {
			return fmt.Errorf("the plugin reported writing %s, which isn't there", path)
		}
	}
	for _, path := range wrote {
		if !slices.Contains(listed, path) {
			return fmt.Errorf("the plugin wrote %s without reporting it", path)
		}
	}
	return nil
}
