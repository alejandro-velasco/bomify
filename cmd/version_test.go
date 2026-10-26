package cmd

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

// runVersion runs "bomify version" with args, returning what it printed.
func runVersion(t *testing.T, args ...string) string {
	t.Helper()
	root, err := NewRootCmd()
	if err != nil {
		t.Fatalf("NewRootCmd() error = %v", err)
	}
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&bytes.Buffer{})
	root.SetArgs(append([]string{"version"}, args...))

	if err := root.Execute(); err != nil {
		t.Fatalf("bomify version %s: %v", strings.Join(args, " "), err)
	}
	return out.String()
}

func TestVersionText(t *testing.T) {
	out := runVersion(t)

	for _, label := range []string{"version:", "commit:", "built:", "go:"} {
		if !strings.Contains(out, label) {
			t.Errorf("output = %q, want a %q line", out, label)
		}
	}
}

// TestVersionJSON covers --format json, and --output, its deprecated
// name, which still works, with a notice: on stderr, but in out here,
// since cobra prints it to a command's output once one is set.
func TestVersionJSON(t *testing.T) {
	for name, test := range map[string]struct {
		args   []string
		notice string
	}{
		"format":    {args: []string{"--format", "json"}},
		"shorthand": {args: []string{"-F", "json"}},
		"output":    {args: []string{"--output", "json"}, notice: "Flag --output has been deprecated, use --format\n"},
	} {
		t.Run(name, func(t *testing.T) {
			out := runVersion(t, test.args...)

			if !strings.HasPrefix(out, test.notice) {
				t.Fatalf("output = %q, want it to start with %q", out, test.notice)
			}
			out = strings.TrimPrefix(out, test.notice)
			var info map[string]string
			if err := json.Unmarshal([]byte(out), &info); err != nil {
				t.Fatalf("output isn't JSON: %v\n%s", err, out)
			}
			for _, key := range []string{"version", "commit", "date", "goVersion"} {
				if _, ok := info[key]; !ok {
					t.Errorf("output = %v, want a %q key", info, key)
				}
			}
		})
	}
}

func TestVersionOutputIsDeprecated(t *testing.T) {
	cmd := versionCmd()

	output := cmd.Flags().Lookup("output")

	if output == nil || output.Deprecated == "" || !output.Hidden {
		t.Errorf("--output = %+v, want it deprecated and hidden", output)
	}
	if cmd.Flags().Lookup("format") == nil {
		t.Errorf("bomify version: missing --format")
	}
}

func TestVersionRefusesUnknownFormats(t *testing.T) {
	root, err := NewRootCmd()
	if err != nil {
		t.Fatalf("NewRootCmd() error = %v", err)
	}
	root.SetOut(&bytes.Buffer{})
	root.SetErr(&bytes.Buffer{})
	root.SetArgs([]string{"version", "--format", "yaml"})

	err = root.Execute()

	if err == nil || !strings.Contains(err.Error(), "must be json or text") {
		t.Errorf("bomify version --format yaml: error = %v, want it to name the formats", err)
	}
}
