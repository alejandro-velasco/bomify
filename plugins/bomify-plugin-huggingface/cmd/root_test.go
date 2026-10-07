package cmd

import (
	"bytes"
	"strings"
	"testing"
)

func TestContract(t *testing.T) {
	root := NewRootCmd()
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetArgs([]string{"contract"})
	if err := root.Execute(); err != nil {
		t.Fatalf("contract: %v", err)
	}
	if want := `{"contracts":{"component":1,"sbom":1}}`; strings.TrimSpace(out.String()) != want {
		t.Errorf("stdout = %s, want %s", out.String(), want)
	}
}
