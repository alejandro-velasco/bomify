package scan

import (
	"testing"

	"github.com/package-url/packageurl-go"
)

func TestImageReference(t *testing.T) {
	tests := []struct {
		name string
		purl string
		want string
	}{
		{"plain tag", "pkg:oci/nginx@1.27", "nginx:1.27"},
		{"digest version", "pkg:oci/nginx@sha256:abcd1234", "nginx@sha256:abcd1234"},
		{"no version", "pkg:oci/nginx", "nginx"},
		{"namespace", "pkg:docker/library/nginx@1.27", "library/nginx:1.27"},
		{"tag qualifier preferred over version", "pkg:oci/nginx@1.27?tag=latest", "nginx:latest"},
		{
			"repository_url qualifier overrides name/namespace",
			"pkg:oci/nginx@1.27?repository_url=registry.example.com/mirror/nginx",
			"registry.example.com/mirror/nginx:1.27",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			purl, err := packageurl.FromString(tt.purl)
			if err != nil {
				t.Fatalf("parse purl %q: %v", tt.purl, err)
			}

			if got := imageReference(purl); got != tt.want {
				t.Errorf("imageReference(%q) = %q, want %q", tt.purl, got, tt.want)
			}
		})
	}
}

func TestSupportedTypesIncludesImageTypes(t *testing.T) {
	types := make(map[string]bool)
	for _, t := range SupportedTypes() {
		types[t] = true
	}

	for imageType := range imageTypes {
		if !types[imageType] {
			t.Errorf("SupportedTypes() missing image type %q", imageType)
		}
	}
}
