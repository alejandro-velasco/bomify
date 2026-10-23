package cmd

import (
	"bytes"
	"strings"
	"testing"

	"github.com/alejandro-velasco/bomify/internal/deploy"
)

func TestDeployCmdHasGenerate(t *testing.T) {
	root, err := NewRootCmd()
	if err != nil {
		t.Fatalf("NewRootCmd() error = %v", err)
	}

	generate, _, err := root.Find([]string{"deploy", "generate"})
	if err != nil || generate.Use != "generate <reference>" || generate.RunE == nil {
		t.Fatalf("bomify deploy generate: %v, %+v", err, generate)
	}
	for _, name := range []string{"file", "output", "replace", "verify", "verify-option", "verify-provenance", "insecure-skip-verify"} {
		if generate.Flags().Lookup(name) == nil {
			t.Errorf("bomify deploy generate: missing --%s", name)
		}
	}
}

func TestDeployGenerateRequiresFileOutputAndAReference(t *testing.T) {
	for name, test := range map[string]struct {
		args    []string
		wantErr string
	}{
		"no file":      {args: []string{"deploy", "generate", "registry.example.com/app:1", "--output", "out"}, wantErr: `required flag(s) "file" not set`},
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

func TestWriteGenerated(t *testing.T) {
	index := deploy.Index{Deployments: []deploy.Generated{
		{Name: "frontend", Type: "helm", Files: []string{"frontend/values.yaml"}, Instructions: "helm upgrade --install frontend oci://registry.example.com/app@sha256:abc --values values.yaml"},
		{Name: "local", Type: "compose", Files: []string{"local/compose.yaml", "local/.env"}},
	}}
	var out bytes.Buffer

	writeGenerated(&out, index)

	want := "frontend (helm): frontend/values.yaml\n" +
		"  in frontend/: helm upgrade --install frontend oci://registry.example.com/app@sha256:abc --values values.yaml\n" +
		"local (compose): local/compose.yaml, local/.env\n"
	if out.String() != want {
		t.Errorf("output:\n%s\nwant:\n%s", out.String(), want)
	}
}
