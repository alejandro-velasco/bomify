package cmd

import (
	"os"
	"strings"
	"testing"

	"github.com/alejandro-velasco/bomify/internal/layout"
)

func TestRootChecksDataDirVersion(t *testing.T) {
	// A pre-alpha data directory: content, but no version.
	unversioned := t.TempDir()
	if err := os.MkdirAll(layout.Plugins(unversioned), 0o755); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		args    []string
		refused bool
	}{
		{args: []string{"packages"}, refused: true},
		{args: []string{"trust", "list"}, refused: true},
		{args: []string{"version"}},
		{args: []string{"help"}},
		{args: []string{"completion", "bash"}},
		{args: []string{"--docs-dir", t.TempDir()}},
	}
	for _, tt := range tests {
		t.Run(strings.Join(tt.args, " "), func(t *testing.T) {
			_, err := runRootCmd(t, unversioned, tt.args...)
			if tt.refused && (err == nil || !strings.Contains(err.Error(), "pre-alpha")) {
				t.Fatalf("err = %v, want the unversioned data directory refused", err)
			}
			if !tt.refused && err != nil {
				t.Fatalf("err = %v, want the data directory left unchecked", err)
			}
		})
	}
}
