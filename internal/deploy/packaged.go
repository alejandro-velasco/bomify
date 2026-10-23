package deploy

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/alejandro-velasco/bomify/internal/fsutil"
	"github.com/alejandro-velasco/bomify/internal/layout"
	"github.com/alejandro-velasco/bomify/internal/oci/pull"
)

// FileName is what a package's deployment file is called among its
// deployments: in "<dataDir>/deployments/<sbomHash>", and in the package's
// deployments manifest.
const FileName = "deployments.yaml"

// CheckRecordable checks Record would record the deployment file at path,
// without recording it: so a build can fail on it before pulling anything.
func CheckRecordable(path string) error {
	_, _, err := recordable(path)
	return err
}

// recordable checks the deployment file at path can be recorded, and
// returns its directory and the files it names, relative to that: each
// config and overlay, once.
func recordable(path string) (dir string, files []string, err error) {
	file, err := Load(path)
	if err != nil {
		return "", nil, err
	}
	if err := Check(file); err != nil {
		return "", nil, fmt.Errorf("deployment file %s: %w", path, err)
	}
	dir, err = filepath.Abs(filepath.Dir(path))
	if err != nil {
		return "", nil, err
	}
	files, err = packagedFiles(file, dir)
	if err != nil {
		return "", nil, fmt.Errorf("deployment file %s: %w", path, err)
	}
	return dir, files, nil
}

// Record records the deployment file at path, and every config and overlay
// it names, as the deployments of the build of sbomHash in dataDir (see
// layout.Deployments), replacing any recorded before, for push and save to
// package. Every path the file names must be inside its directory, so it
// still names the same file once packaged.
func Record(dataDir, sbomHash, path string) error {
	dir, files, err := recordable(path)
	if err != nil {
		return err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	write := func(stageDir string) error {
		if err := fsutil.WriteFileAtomic(filepath.Join(stageDir, FileName), data); err != nil {
			return err
		}
		for _, relative := range files {
			content, err := os.ReadFile(filepath.Join(dir, relative))
			if err != nil {
				return err
			}
			if err := fsutil.WriteFileAtomic(filepath.Join(stageDir, relative), content); err != nil {
				return err
			}
		}
		return nil
	}
	return pull.WriteInto(layout.Deployments(dataDir, sbomHash), true, write)
}

// packagedFiles returns the configs and overlays file names, relative to
// dir, the deployment file's, each once, failing on one outside dir, or
// that would take the deployment file's own place among its deployments.
func packagedFiles(file File, dir string) ([]string, error) {
	var errs []error
	seen := map[string]bool{}
	var files []string
	for _, deployment := range file.Deployments {
		for _, path := range append([]string{deployment.Config}, deployment.Overlays...) {
			if path == "" {
				continue
			}
			relative, err := filepath.Rel(dir, path)
			if err != nil || !filepath.IsLocal(relative) {
				errs = append(errs, fmt.Errorf("deployment %q: %s isn't inside the deployment file's directory, so it can't be packaged", deployment.Name, path))
				continue
			}
			if relative == FileName {
				errs = append(errs, fmt.Errorf("deployment %q: a template can't be called %s, the deployment file's name in a package", deployment.Name, FileName))
				continue
			}
			if !seen[relative] {
				seen[relative] = true
				files = append(files, relative)
			}
		}
	}
	return files, errors.Join(errs...)
}

// LoadPackaged loads the deployments in dir, a package's: its deployment
// file, FileName, as Load does, refusing one that names a file outside
// dir, which would be one of the user's own, not one the package carries.
func LoadPackaged(dir string) (File, error) {
	file, err := Load(filepath.Join(dir, FileName))
	if err != nil {
		return File{}, err
	}
	if _, err := packagedFiles(file, dir); err != nil {
		return File{}, fmt.Errorf("the package's deployments: %w", err)
	}
	return file, nil
}
