package transfer

import (
	"encoding/json"
	"io/fs"
	"strings"
	"testing"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

func TestLayerLabel(t *testing.T) {
	hash := strings.Repeat("0123456789abcdef", 4)
	purl := "pkg:huggingface/org/model@abc"
	for name, tc := range map[string]struct {
		purl string
		want string
	}{
		"with a purl": {purl, "0123456789ab " + purl},
		"without one": {"", hash},
	} {
		if got := LayerLabel(tc.purl, hash); got != tc.want {
			t.Errorf("%s: LayerLabel = %q, want %q", name, got, tc.want)
		}
	}
}

// TestFileBlobJSON pins the files map's file format: a mode is octal, and
// reads back as written.
func TestFileBlobJSON(t *testing.T) {
	blob := NewFileBlob("dir/model.gguf", fs.ModeDir|0o755, ocispec.Descriptor{})
	data, err := json.Marshal(blob)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"mode":"0755"`) {
		t.Errorf("JSON = %s, want mode 0755", data)
	}

	var parsed FileBlob
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if parsed != blob {
		t.Errorf("parsed %+v, want %+v", parsed, blob)
	}
}

func TestFileModeRejects(t *testing.T) {
	for _, mode := range []string{`"rwx"`, `"4755"`, `"0644x"`, `""`, `420`} {
		var parsed FileMode
		if err := json.Unmarshal([]byte(mode), &parsed); err == nil {
			t.Errorf("mode %s parsed as %o, want an error", mode, parsed)
		}
	}
}

func TestIsSafePath(t *testing.T) {
	for path, want := range map[string]bool{
		"f":           true,
		"dir/f":       true,
		"":            false,
		"../f":        false,
		"dir/../../f": false,
		"/etc/passwd": false,
		`dir\f`:       false,
		"f\x00":       false,
	} {
		if got := isSafePath(path); got != want {
			t.Errorf("isSafePath(%q) = %v, want %v", path, got, want)
		}
	}
}
