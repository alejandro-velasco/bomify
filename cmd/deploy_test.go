package cmd

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/alejandro-velasco/bomify/internal/deploy"
)

// generatedIndex is what writeGenerated's tests print.
var generatedIndex = deploy.Index{
	Package: "registry.example.com/app@sha256:abc",
	Deployments: []deploy.Generated{
		{Name: "frontend", Type: "helm", Files: []string{"frontend/values.yaml"}, Instructions: "helm upgrade --install frontend oci://registry.example.com/app@sha256:abc --values values.yaml"},
		{Name: "local", Type: "compose", Files: []string{"local/compose.yaml", "local/.env"}, DependsOn: []string{"frontend"}},
	},
}

// generatedText is generatedIndex as text.
const generatedText = "frontend (helm): frontend/values.yaml\n" +
	"  in frontend/: helm upgrade --install frontend oci://registry.example.com/app@sha256:abc --values values.yaml\n" +
	"local (compose): local/compose.yaml, local/.env\n"

func TestDeployCmdHasGenerate(t *testing.T) {
	root, err := NewRootCmd()
	if err != nil {
		t.Fatalf("NewRootCmd() error = %v", err)
	}

	generate, _, err := root.Find([]string{"deploy", "generate"})
	if err != nil || generate.Use != "generate <reference>" || generate.RunE == nil {
		t.Fatalf("bomify deploy generate: %v, %+v", err, generate)
	}
	for _, name := range []string{"file", "output", "format", "replace", "verify", "verify-option", "verify-provenance", "insecure-skip-verify"} {
		if generate.Flags().Lookup(name) == nil {
			t.Errorf("bomify deploy generate: missing --%s", name)
		}
	}
}

func TestDeployGenerateRequiresOutputAndAReference(t *testing.T) {
	for name, test := range map[string]struct {
		args    []string
		wantErr string
	}{
		"no output":    {args: []string{"deploy", "generate", "registry.example.com/app:1", "--file", "deploy.yaml"}, wantErr: `required flag(s) "output" not set`},
		"no reference": {args: []string{"deploy", "generate", "--file", "deploy.yaml", "--output", "out"}, wantErr: "accepts 1 arg(s), received 0"},
	} {
		t.Run(name, func(t *testing.T) {
			root, err := NewRootCmd()
			if err != nil {
				t.Fatalf("NewRootCmd() error = %v", err)
			}
			root.SetOut(&bytes.Buffer{})
			root.SetErr(&bytes.Buffer{})
			root.SetArgs(test.args)

			err = root.Execute()

			if err == nil || !strings.Contains(err.Error(), test.wantErr) {
				t.Errorf("bomify %s: error = %v, want it to contain %q", strings.Join(test.args, " "), err, test.wantErr)
			}
		})
	}
}

func TestWriteGeneratedText(t *testing.T) {
	var out bytes.Buffer

	if err := writeGenerated(&out, generatedIndex, formatTypeText); err != nil {
		t.Fatalf("writeGenerated: %v", err)
	}

	if out.String() != generatedText {
		t.Errorf("output:\n%s\nwant:\n%s", out.String(), generatedText)
	}
}

// TestWriteGeneratedJSON covers --format json: the index, all of it, as
// one JSON document that decodes back to the same index.
func TestWriteGeneratedJSON(t *testing.T) {
	var out bytes.Buffer

	if err := writeGenerated(&out, generatedIndex, formatTypeJSON); err != nil {
		t.Fatalf("writeGenerated: %v", err)
	}

	var got deploy.Index
	decoder := json.NewDecoder(&out)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&got); err != nil {
		t.Fatalf("decode output: %v", err)
	}
	if !reflect.DeepEqual(got, generatedIndex) {
		t.Errorf("decoded output = %+v, want %+v", got, generatedIndex)
	}
	if decoder.More() {
		t.Errorf("output has more than one JSON document")
	}
}

func TestDeployCmdHasList(t *testing.T) {
	root, err := NewRootCmd()
	if err != nil {
		t.Fatalf("NewRootCmd() error = %v", err)
	}

	list, _, err := root.Find([]string{"deploy", "list"})
	if err != nil || list.Use != "list <reference>" || list.RunE == nil {
		t.Fatalf("bomify deploy list: %v, %+v", err, list)
	}
	for _, name := range []string{"verify", "verify-option", "verify-provenance", "insecure-skip-verify"} {
		if list.Flags().Lookup(name) == nil {
			t.Errorf("bomify deploy list: missing --%s", name)
		}
	}
}

func TestWriteDeploymentTable(t *testing.T) {
	packaged := t.TempDir()
	disabled := false
	chart := deploy.Option("podinfo")
	release := deploy.Option("shop")
	file := deploy.File{Deployments: []deploy.Deployment{
		{
			Name:      "web",
			Type:      "helm",
			Options:   map[string]*deploy.Option{"release": &release, "chart": &chart},
			Config:    filepath.Join(packaged, "templates", "web.yaml.tmpl"),
			Overlays:  []string{filepath.Join(packaged, "overrides", "web.yaml.tmpl")},
			DependsOn: []string{"infra"},
		},
		{Name: "infra", Type: "terraform", Enabled: &disabled},
	}}
	var out bytes.Buffer

	if err := writeDeploymentTable(&out, file, packaged); err != nil {
		t.Fatalf("writeDeploymentTable: %v", err)
	}

	want := "NAME               TYPE        OPTIONS                       CONFIG                    OVERLAYS                  DEPENDS ON\n" +
		"web                helm        chart=podinfo, release=shop   templates/web.yaml.tmpl   overrides/web.yaml.tmpl   infra\n" +
		"infra (disabled)   terraform   -                             -                         -                         -\n"
	if out.String() != want {
		t.Errorf("table:\n%s\nwant:\n%s", out.String(), want)
	}
}
