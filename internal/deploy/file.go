// Package deploy generates what deployment tools deploy from a package in
// a registry, through deployment plugins (see
// plugins/contracts/deployment/v1/CONTRACT.md): it reads deployment files,
// describes the package to each plugin, and runs them.
package deploy

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"sigs.k8s.io/yaml"

	"github.com/alejandro-velasco/bomify/internal/oci/transfer"
)

// File is a deployment file: the named deployments to generate.
type File struct {
	Deployments []Deployment `json:"deployments"`
}

// Deployment is one deployment of a File.
type Deployment struct {
	// Name is unique in the file, and names its output directory.
	Name string `json:"name"`
	// Type is the deployment medium, and so the plugin:
	// bomify-plugin-<type>.
	Type string `json:"type"`
	// Options are its key=value settings. A null value is a removal, for
	// a file laid over another (see Lay).
	Options map[string]*Option `json:"options,omitempty"`
	// Config and Overlays are its files, absolute once loaded.
	Config   string   `json:"config,omitempty"`
	Overlays []string `json:"overlays,omitempty"`
	// DependsOn names the deployments to apply before this one.
	DependsOn []string `json:"dependsOn,omitempty"`
	// Enabled, if false, skips the deployment.
	Enabled *bool `json:"enabled,omitempty"`
}

// Option is one option's value: any scalar, which the plugin gets as
// text, so "replicas: 3" needs no quotes.
type Option string

// UnmarshalJSON reads a string, number, or boolean as its text, and
// refuses anything else.
func (o *Option) UnmarshalJSON(data []byte) error {
	var value any
	if err := json.Unmarshal(data, &value); err != nil {
		return err
	}
	switch typed := value.(type) {
	case string:
		*o = Option(typed)
	case float64, bool:
		*o = Option(data)
	default:
		return fmt.Errorf("option value %s isn't a string, number, or boolean", data)
	}
	return nil
}

// Load reads the deployment file at path, YAML or JSON, refusing unknown
// keys, and makes its paths absolute, relative to it. It checks only what
// the file alone can get wrong; Lay and Check check the rest.
func Load(path string) (File, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return File{}, fmt.Errorf("read deployment file: %w", err)
	}
	data, err = yaml.YAMLToJSON(data)
	if err != nil {
		return File{}, fmt.Errorf("parse deployment file %s: %w", path, err)
	}
	var file File
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&file); err != nil {
		return File{}, fmt.Errorf("parse deployment file %s: %w", path, err)
	}

	dir, err := filepath.Abs(filepath.Dir(path))
	if err != nil {
		return File{}, fmt.Errorf("resolve %s: %w", path, err)
	}
	var errs []error
	names := map[string]bool{}
	for index := range file.Deployments {
		deployment := &file.Deployments[index]
		if !transfer.IsSafeFilename(deployment.Name) {
			errs = append(errs, fmt.Errorf("deployments[%d]: name %q isn't usable as a directory name", index, deployment.Name))
		} else if names[deployment.Name] {
			errs = append(errs, fmt.Errorf("deployments[%d]: name %q is taken", index, deployment.Name))
		}
		names[deployment.Name] = true
		if deployment.Config != "" {
			deployment.Config = resolve(dir, deployment.Config)
		}
		for overlay := range deployment.Overlays {
			deployment.Overlays[overlay] = resolve(dir, deployment.Overlays[overlay])
		}
	}
	if err := errors.Join(errs...); err != nil {
		return File{}, fmt.Errorf("deployment file %s: %w", path, err)
	}
	return file, nil
}

// resolve is path, made absolute against dir unless it already is.
func resolve(dir, path string) string {
	if filepath.IsAbs(path) {
		return path
	}
	return filepath.Join(dir, path)
}

// Lay lays over on base, deployment by deployment, matched by name, and
// returns the result: a deployment of over's with a name base has
// changes base's, as the contract's "Overriding the package's" describes,
// and one with a new name is added, after base's.
func Lay(base, over File) (File, error) {
	laid := File{Deployments: slices.Clone(base.Deployments)}
	var errs []error
	for _, overlay := range over.Deployments {
		index := slices.IndexFunc(laid.Deployments, func(d Deployment) bool { return d.Name == overlay.Name })
		if index < 0 {
			laid.Deployments = append(laid.Deployments, overlay)
			continue
		}
		merged, err := layDeployment(laid.Deployments[index], overlay)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		laid.Deployments[index] = merged
	}
	if err := errors.Join(errs...); err != nil {
		return File{}, err
	}
	return laid, nil
}

// layDeployment lays over on base, two deployments of the same name.
func layDeployment(base, over Deployment) (Deployment, error) {
	if over.Type != "" && over.Type != base.Type {
		return Deployment{}, fmt.Errorf("deployment %q: can't change its type from %q to %q", base.Name, base.Type, over.Type)
	}
	merged := base
	merged.Options = map[string]*Option{}
	for key, value := range base.Options {
		merged.Options[key] = value
	}
	for key, value := range over.Options {
		if value == nil {
			delete(merged.Options, key)
			continue
		}
		merged.Options[key] = value
	}
	if over.Config != "" {
		merged.Config = over.Config
	}
	merged.Overlays = append(slices.Clone(base.Overlays), over.Overlays...)
	if over.DependsOn != nil {
		merged.DependsOn = over.DependsOn
	}
	if over.Enabled != nil {
		merged.Enabled = over.Enabled
	}
	return merged, nil
}

// Check checks a file to generate from, once any Lay is done: every
// deployment has a type, depends only on deployments that exist and are
// enabled, and no deployment depends, however indirectly, on itself.
func Check(file File) error {
	var errs []error
	// Every deployment's state first, since one may depend on a later one.
	enabled := map[string]bool{}
	for _, deployment := range file.Deployments {
		enabled[deployment.Name] = deployment.Enabled == nil || *deployment.Enabled
	}
	for _, deployment := range file.Deployments {
		if !enabled[deployment.Name] {
			continue
		}
		if !transfer.IsSafeFilename(deployment.Type) {
			errs = append(errs, fmt.Errorf("deployment %q: type %q isn't a plugin's name", deployment.Name, deployment.Type))
		}
		for _, dependency := range deployment.DependsOn {
			isEnabled, exists := enabled[dependency]
			if !exists {
				errs = append(errs, fmt.Errorf("deployment %q depends on %q, which there isn't", deployment.Name, dependency))
			} else if !isEnabled {
				errs = append(errs, fmt.Errorf("deployment %q depends on %q, which is disabled", deployment.Name, dependency))
			}
		}
	}
	if err := checkCycles(file); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

// checkCycles fails if a deployment of file depends on itself, however
// indirectly, naming the cycle. It's a depth-first search that marks each
// deployment as it goes: one met again while still being visited is on
// the current path, so the path from it back to itself is a cycle.
func checkCycles(file File) error {
	search := cycleSearch{
		dependsOn: map[string][]string{},
		state:     map[string]visitState{},
	}
	for _, deployment := range file.Deployments {
		search.dependsOn[deployment.Name] = deployment.DependsOn
	}
	for _, deployment := range file.Deployments {
		if err := search.visit(deployment.Name, nil); err != nil {
			return err
		}
	}
	return nil
}

// visitState is how far cycleSearch has got with a deployment.
type visitState int

const (
	unvisited visitState = iota
	// visiting: on the current path, its dependencies still being searched.
	visiting
	// done: it and everything it depends on are free of cycles.
	done
)

// cycleSearch is checkCycles' search: each deployment's dependencies, and
// how far it has got with each.
type cycleSearch struct {
	dependsOn map[string][]string
	state     map[string]visitState
}

// visit searches name's dependencies, path being the deployments that led
// to it, and fails on a cycle.
func (s *cycleSearch) visit(name string, path []string) error {
	if s.state[name] == done {
		return nil
	}
	if s.state[name] == visiting {
		start := slices.Index(path, name)
		cycle := append(slices.Clone(path[start:]), name)
		return fmt.Errorf("deployments depend on each other in a cycle: %s", strings.Join(cycle, " -> "))
	}
	s.state[name] = visiting
	for _, dependency := range s.dependsOn[name] {
		if err := s.visit(dependency, append(path, name)); err != nil {
			return err
		}
	}
	s.state[name] = done
	return nil
}
