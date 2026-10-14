package transfer

import (
	"maps"
	"strings"
	"testing"
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

// TestFileRoundTrip pins the file layer format: ParseFile reads back
// exactly what Annotations writes.
func TestFileRoundTrip(t *testing.T) {
	file := File{
		Path: "dir/model.gguf",
		Mode: 0o755,
	}
	annotations := file.Annotations("pkg:huggingface/org/model@abc")
	if got := annotations[AnnotationPurl]; got != "pkg:huggingface/org/model@abc" {
		t.Errorf("purl annotation = %q", got)
	}

	parsed, err := ParseFile(annotations)
	if err != nil {
		t.Fatalf("ParseFile: %v", err)
	}
	if parsed != file {
		t.Errorf("ParseFile = %+v, want %+v", parsed, file)
	}
}

func TestParseFileRejects(t *testing.T) {
	valid := File{Path: "f", Mode: 0o644}.Annotations("p")
	for name, tc := range map[string]struct {
		key, value, want string
	}{
		"escaping path": {AnnotationFilePath, "../f", "outside its component"},
		"backslash":     {AnnotationFilePath, `dir\f`, "outside its component"},
		"NUL byte":      {AnnotationFilePath, "f\x00", "outside its component"},
		"bad mode":      {AnnotationFileMode, "rwx", "invalid file mode"},
		"mode too wide": {AnnotationFileMode, "4755", "invalid file mode"},
	} {
		annotations := maps.Clone(valid)
		annotations[tc.key] = tc.value
		if _, err := ParseFile(annotations); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: ParseFile = %v, want an error containing %q", name, err, tc.want)
		}
	}
}
