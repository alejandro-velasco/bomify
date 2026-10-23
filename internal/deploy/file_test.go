package deploy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeFile writes content to name in dir, returning its path.
func writeFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoad(t *testing.T) {
	dir := t.TempDir()
	path := writeFile(t, dir, "deploy.yaml", `
deployments:
  - name: backend
    type: helm
    options:
      chart: chart-b
      replicas: 3
      debug: true
    config: templates/backend.yaml.tmpl
    overlays:
      - overrides.yaml.tmpl
    dependsOn:
      - infra
  - name: infra
    type: terraform
`)

	file, err := Load(path)

	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(file.Deployments) != 2 {
		t.Fatalf("deployments = %+v, want 2", file.Deployments)
	}
	backend := file.Deployments[0]
	for key, want := range map[string]string{"chart": "chart-b", "replicas": "3", "debug": "true"} {
		if got := backend.Options[key]; got == nil || string(*got) != want {
			t.Errorf("option %s = %v, want %q", key, got, want)
		}
	}
	if backend.Config != filepath.Join(dir, "templates", "backend.yaml.tmpl") {
		t.Errorf("config = %q, want it relative to the file", backend.Config)
	}
	if len(backend.Overlays) != 1 || backend.Overlays[0] != filepath.Join(dir, "overrides.yaml.tmpl") {
		t.Errorf("overlays = %q, want them relative to the file", backend.Overlays)
	}
}

func TestLoadRejects(t *testing.T) {
	for name, test := range map[string]struct {
		content string
		want    string
	}{
		"an unknown key":         {content: "deployments:\n  - name: a\n    type: helm\n    chart: x\n", want: "unknown field"},
		"a name taken twice":     {content: "deployments:\n  - name: a\n    type: helm\n  - name: a\n    type: helm\n", want: "is taken"},
		"a name not a dir":       {content: "deployments:\n  - name: ../a\n    type: helm\n", want: "isn't usable"},
		"an option that's a map": {content: "deployments:\n  - name: a\n    type: helm\n    options:\n      chart:\n        name: x\n", want: "isn't a string"},
	} {
		t.Run(name, func(t *testing.T) {
			path := writeFile(t, t.TempDir(), "deploy.yaml", test.content)

			_, err := Load(path)

			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Errorf("Load = %v, want an error containing %q", err, test.want)
			}
		})
	}
}

// option is an Option's address, for literals.
func option(value string) *Option {
	o := Option(value)
	return &o
}

func TestLay(t *testing.T) {
	disabled := false
	base := File{Deployments: []Deployment{
		{Name: "frontend", Type: "helm", Options: map[string]*Option{"chart": option("chart-a"), "release": option("app"), "debug": option("true")}, Config: "/author/frontend.tmpl", Overlays: []string{"/author/extra.tmpl"}, DependsOn: []string{"infra"}},
		{Name: "infra", Type: "terraform"},
	}}
	over := File{Deployments: []Deployment{
		{Name: "frontend", Options: map[string]*Option{"release": option("web"), "debug": nil}, Overlays: []string{"/user/overrides.tmpl"}},
		{Name: "infra", Enabled: &disabled},
		{Name: "extra", Type: "compose"},
	}}

	laid, err := Lay(base, over)

	if err != nil {
		t.Fatalf("Lay: %v", err)
	}
	if len(laid.Deployments) != 3 || laid.Deployments[2].Name != "extra" {
		t.Fatalf("deployments = %+v, want base's then the new one", laid.Deployments)
	}
	frontend := laid.Deployments[0]
	if string(*frontend.Options["chart"]) != "chart-a" || string(*frontend.Options["release"]) != "web" {
		t.Errorf("options = %v, want chart kept and release replaced", frontend.Options)
	}
	if _, ok := frontend.Options["debug"]; ok {
		t.Error("a null option didn't remove the base's")
	}
	if frontend.Config != "/author/frontend.tmpl" {
		t.Errorf("config = %q, want the author's kept", frontend.Config)
	}
	if strings.Join(frontend.Overlays, ",") != "/author/extra.tmpl,/user/overrides.tmpl" {
		t.Errorf("overlays = %q, want the author's then the user's", frontend.Overlays)
	}
	if strings.Join(frontend.DependsOn, ",") != "infra" {
		t.Errorf("dependsOn = %q, want the author's kept", frontend.DependsOn)
	}
	if infra := laid.Deployments[1]; infra.Enabled == nil || *infra.Enabled {
		t.Errorf("infra enabled = %v, want false", infra.Enabled)
	}
	// Lay leaves base as it was.
	if string(*base.Deployments[0].Options["release"]) != "app" || len(base.Deployments[0].Overlays) != 1 {
		t.Errorf("base changed: %+v", base.Deployments[0])
	}
}

func TestLayRefusesChangingAType(t *testing.T) {
	base := File{Deployments: []Deployment{{Name: "app", Type: "helm"}}}
	over := File{Deployments: []Deployment{{Name: "app", Type: "compose"}}}

	if _, err := Lay(base, over); err == nil || !strings.Contains(err.Error(), "can't change its type") {
		t.Errorf("Lay = %v, want it to refuse changing the type", err)
	}
}

func TestCheck(t *testing.T) {
	disabled := false
	for name, test := range map[string]struct {
		deployments []Deployment
		want        string
	}{
		"fine":                 {deployments: []Deployment{{Name: "a", Type: "helm", DependsOn: []string{"b"}}, {Name: "b", Type: "terraform"}}},
		"no type":              {deployments: []Deployment{{Name: "a"}}, want: "isn't a plugin's name"},
		"a missing dependency": {deployments: []Deployment{{Name: "a", Type: "helm", DependsOn: []string{"b"}}}, want: "which there isn't"},
		"a disabled dependency": {
			deployments: []Deployment{{Name: "a", Type: "helm", DependsOn: []string{"b"}}, {Name: "b", Type: "helm", Enabled: &disabled}},
			want:        "which is disabled",
		},
		"a cycle": {
			deployments: []Deployment{{Name: "a", Type: "helm", DependsOn: []string{"b"}}, {Name: "b", Type: "helm", DependsOn: []string{"a"}}},
			want:        "cycle",
		},
		"a disabled deployment without a type": {deployments: []Deployment{{Name: "a", Enabled: &disabled}}},
	} {
		t.Run(name, func(t *testing.T) {
			err := Check(File{Deployments: test.deployments})

			if test.want == "" {
				if err != nil {
					t.Errorf("Check = %v, want nil", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Errorf("Check = %v, want an error containing %q", err, test.want)
			}
		})
	}
}
