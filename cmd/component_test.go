package cmd

import (
	"bytes"
	"fmt"
	"strings"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"

	"github.com/alejandro-velasco/bomify/internal/oci/pull"
	"github.com/alejandro-velasco/bomify/internal/oci/transfer"
)

func TestComponentCmdHasListAndPull(t *testing.T) {
	component := componentCmd()

	want := map[string]string{
		"list": "list <reference>",
		"pull": "pull <reference> <component>",
	}
	for name, wantUse := range want {
		found, _, err := component.Find([]string{name})
		if err != nil {
			t.Errorf("bomify component %s: not found: %v", name, err)
			continue
		}
		if found.Use != wantUse {
			t.Errorf("bomify component %s: Use = %q, want %q", name, found.Use, wantUse)
		}
		if found.RunE == nil {
			t.Errorf("bomify component %s: RunE is nil", name)
		}
	}
}

func TestRootHasComponentCommand(t *testing.T) {
	root, err := NewRootCmd()
	if err != nil {
		t.Fatalf("NewRootCmd() error = %v", err)
	}

	found, _, err := root.Find([]string{"component", "pull"})
	if err != nil || found.Name() != "pull" {
		t.Fatalf("bomify component pull: not found (%v)", err)
	}
}

func TestComponentPullFlags(t *testing.T) {
	pullCommand, _, err := componentCmd().Find([]string{"pull"})
	if err != nil {
		t.Fatal(err)
	}

	for _, name := range []string{"output", "replace", "concurrency", "quiet", "verify", "verify-option", "verify-provenance", "insecure-skip-verify"} {
		if pullCommand.Flags().Lookup(name) == nil {
			t.Errorf("bomify component pull: missing --%s", name)
		}
	}
	// Scanning a whole package is "bomify pull"'s: this takes one component.
	for _, name := range []string{"scan", "fail-on", "skip-scan"} {
		if pullCommand.Flags().Lookup(name) != nil {
			t.Errorf("bomify component pull: has --%s, which only whole-package pulls scan for", name)
		}
	}
	if output := pullCommand.Flags().Lookup("output"); output == nil || output.Shorthand != "o" {
		t.Errorf("bomify component pull: --output shorthand = %v, want -o", output)
	}
}

func TestComponentPullRequiresOutputAndTwoArguments(t *testing.T) {
	for _, test := range []struct {
		name    string
		args    []string
		wantErr string
	}{
		{name: "no output", args: []string{"component", "pull", "registry.example.com/app:1", "model"}, wantErr: `required flag(s) "output" not set`},
		{name: "no component", args: []string{"component", "pull", "registry.example.com/app:1", "--output", "out"}, wantErr: "accepts 2 arg(s), received 1"},
		{name: "list without a reference", args: []string{"component", "list"}, wantErr: "accepts 1 arg(s), received 0"},
	} {
		t.Run(test.name, func(t *testing.T) {
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

// filesOf is the files of purl, one of each size in sizes.
func filesOf(purl string, sizes ...int64) transfer.ComponentFiles {
	files := transfer.ComponentFiles{Purl: purl}
	for index, size := range sizes {
		file := transfer.FileBlob{
			Path: fmt.Sprintf("file-%d", index),
			Size: size,
		}
		files.Files = append(files.Files, file)
	}
	return files
}

func TestWriteComponentTable(t *testing.T) {
	components := []pull.PackageComponent{
		{
			Component: cdx.Component{Name: "model", Version: "abc", Type: cdx.ComponentTypeMachineLearningModel, PackageURL: "pkg:huggingface/org/model@abc"},
			Files:     filesOf("pkg:huggingface/org/model@abc", 4<<30, 1<<30, 0),
			Reference: "registry.example.com/app/huggingface/org/model:abc",
		},
		{
			Component: cdx.Component{Name: "nginx", Version: "1.27", Type: cdx.ComponentTypeContainer, PackageURL: "pkg:oci/nginx@1.27"},
			Files:     filesOf("pkg:oci/nginx@1.27", 40<<20, 2<<20),
		},
		{
			Component: cdx.Component{Name: "empty", Version: "1", Type: cdx.ComponentTypeFile, PackageURL: "pkg:generic/empty@1"},
		},
	}
	var out bytes.Buffer

	if err := writeComponentTable(&out, components); err != nil {
		t.Fatalf("writeComponentTable() error = %v", err)
	}

	want := "NAME    VERSION   TYPE             SIZE   REFERENCE\n" +
		"model   abc       huggingface    5.0GiB   registry.example.com/app/huggingface/org/model:abc\n" +
		"nginx   1.27      oci           42.0MiB   -\n" +
		"empty   1         generic             -   -\n"
	if out.String() != want {
		t.Errorf("table:\n%s\nwant:\n%s", out.String(), want)
	}
}

func TestWriteComponentTableWithNoComponents(t *testing.T) {
	var out bytes.Buffer

	if err := writeComponentTable(&out, nil); err != nil {
		t.Fatalf("writeComponentTable() error = %v", err)
	}

	if got := strings.TrimSpace(out.String()); got != "NAME   VERSION   TYPE   SIZE   REFERENCE" {
		t.Errorf("table = %q, want just the header", got)
	}
}
