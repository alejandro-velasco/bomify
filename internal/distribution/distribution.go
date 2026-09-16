// Package distribution manages bomify's per-plugin-kind default remote
// endpoints, recorded in "<baseDir>/conf/distribution.json" and read by
// `bomify distribute` as a fallback for any plugin kind not given a
// --remote kind=endpoint on the command line.
package distribution

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// Entry is one plugin kind's remote configuration in distribution.json.
type Entry struct {
	Endpoint string `json:"endpoint"`
}

// Config is the "<baseDir>/conf/distribution.json" record mapping plugin
// kind to its default remote endpoint.
type Config map[string]Entry

// ConfigPath returns the deterministic path of baseDir's distribution.json.
func ConfigPath(baseDir string) string {
	return filepath.Join(baseDir, "conf", "distribution.json")
}

// Read reads and parses baseDir's distribution.json, returning an empty
// Config if it doesn't exist yet.
func Read(baseDir string) (Config, error) {
	path := ConfigPath(baseDir)

	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return Config{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}

	config := Config{}
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}

	return config, nil
}

// Remotes reads baseDir's distribution.json and flattens it into a
// kind -> endpoint map.
func Remotes(baseDir string) (map[string]string, error) {
	config, err := Read(baseDir)
	if err != nil {
		return nil, err
	}

	remotes := make(map[string]string, len(config))
	for kind, entry := range config {
		remotes[kind] = entry.Endpoint
	}

	return remotes, nil
}

// SetEndpoint sets kind's default remote endpoint in
// "<baseDir>/conf/distribution.json", merging into whatever is already
// there. Calling it again for the same kind overwrites its endpoint.
func SetEndpoint(baseDir, kind, endpoint string) error {
	config, err := Read(baseDir)
	if err != nil {
		return err
	}

	config[kind] = Entry{Endpoint: endpoint}

	return writeConfig(baseDir, config)
}

// writeConfig writes config to baseDir's distribution.json.
func writeConfig(baseDir string, config Config) error {
	path := ConfigPath(baseDir)

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("create conf directory: %w", err)
	}

	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(config); err != nil {
		return fmt.Errorf("marshal distribution config: %w", err)
	}

	if err := os.WriteFile(path, buf.Bytes(), 0o644); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}

	return nil
}
