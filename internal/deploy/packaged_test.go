package deploy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/alejandro-velasco/bomify/internal/layout"
)

const sbomHash = "abc123"

func TestRecord(t *testing.T) {
	src := t.TempDir()
	if err := os.MkdirAll(filepath.Join(src, "templates"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(src, "templates"), "web.yaml.tmpl", "replicas: 2\n")
	writeFile(t, src, "overrides.yaml.tmpl", "replicas: 3\n")
	deployFile := `deployments:
  - name: web
    type: helm
    config: templates/web.yaml.tmpl
    overlays:
      - overrides.yaml.tmpl
  - name: api
    type: helm
    config: templates/web.yaml.tmpl
`
	path := writeFile(t, src, "deploy.yaml", deployFile)
	dataDir := t.TempDir()

	if err := Record(dataDir, sbomHash, path); err != nil {
		t.Fatalf("Record: %v", err)
	}

	dir := layout.Deployments(dataDir, sbomHash)
	for name, want := range map[string]string{
		FileName: deployFile,
		filepath.Join("templates", "web.yaml.tmpl"): "replicas: 2\n",
		"overrides.yaml.tmpl":                       "replicas: 3\n",
	} {
		got, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil || string(got) != want {
			t.Errorf("%s = %q, %v, want %q", name, got, err, want)
		}
	}

	file, err := LoadPackaged(dir)
	if err != nil {
		t.Fatalf("LoadPackaged: %v", err)
	}
	if file.Deployments[0].Config != filepath.Join(dir, "templates", "web.yaml.tmpl") {
		t.Errorf("config = %q, want it inside the recorded deployments", file.Deployments[0].Config)
	}
}

func TestRecordReplacesWhatWasRecorded(t *testing.T) {
	src := t.TempDir()
	writeFile(t, src, "old.tmpl", "old: true\n")
	writeFile(t, src, "new.tmpl", "new: true\n")
	old := writeFile(t, src, "old.yaml", "deployments:\n  - name: web\n    type: helm\n    config: old.tmpl\n")
	updated := writeFile(t, src, "new.yaml", "deployments:\n  - name: web\n    type: helm\n    config: new.tmpl\n")
	dataDir := t.TempDir()

	if err := Record(dataDir, sbomHash, old); err != nil {
		t.Fatal(err)
	}
	if err := Record(dataDir, sbomHash, updated); err != nil {
		t.Fatal(err)
	}

	dir := layout.Deployments(dataDir, sbomHash)
	if _, err := os.Stat(filepath.Join(dir, "old.tmpl")); !os.IsNotExist(err) {
		t.Errorf("the first recording's template is still there: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "new.tmpl")); err != nil {
		t.Errorf("the second recording's template is missing: %v", err)
	}
}

func TestRecordRefusesFilesItCantPackage(t *testing.T) {
	outside := t.TempDir()
	outsideTemplate := writeFile(t, outside, "secret.tmpl", "x: 1\n")
	for name, test := range map[string]struct {
		config string
		want   string
	}{
		"a path up":                  {config: "../secret.tmpl", want: "isn't inside"},
		"an absolute path":           {config: outsideTemplate, want: "isn't inside"},
		"the deployment file's name": {config: FileName, want: "can't be called"},
	} {
		t.Run(name, func(t *testing.T) {
			src := filepath.Join(t.TempDir(), "src")
			if err := os.Mkdir(src, 0o755); err != nil {
				t.Fatal(err)
			}
			writeFile(t, src, FileName, "x: 1\n")
			path := writeFile(t, src, "deploy.yaml", "deployments:\n  - name: web\n    type: helm\n    config: "+test.config+"\n")
			dataDir := t.TempDir()

			err := Record(dataDir, sbomHash, path)

			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Errorf("Record = %v, want an error containing %q", err, test.want)
			}
			if _, err := os.Stat(layout.Deployments(dataDir, sbomHash)); !os.IsNotExist(err) {
				t.Errorf("deployments recorded despite the error: %v", err)
			}
		})
	}
}

// TestLoadPackagedRefusesAPathOutside covers a package whose deployment
// file names one of the user's own files, which generating would read.
func TestLoadPackagedRefusesAPathOutside(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, FileName, "deployments:\n  - name: web\n    type: helm\n    config: ../../.ssh/id_rsa\n")

	_, err := LoadPackaged(dir)

	if err == nil || !strings.Contains(err.Error(), "isn't inside") {
		t.Errorf("LoadPackaged = %v, want it to refuse the path", err)
	}
}
