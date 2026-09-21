package image

import "testing"

func TestResolve(t *testing.T) {
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
			got, err := Resolve(tt.purl)
			if err != nil {
				t.Fatalf("Resolve(%q) error = %v", tt.purl, err)
			}
			if got != tt.want {
				t.Errorf("Resolve(%q) = %q, want %q", tt.purl, got, tt.want)
			}
		})
	}
}

func TestResolveInvalidPurl(t *testing.T) {
	if _, err := Resolve("not-a-purl"); err == nil {
		t.Fatal("Resolve() with an unparseable purl: expected error, got nil")
	}
}

func TestLocation(t *testing.T) {
	tests := []struct {
		name string
		purl string
		want string
	}{
		{"no namespace, no prefix left", "pkg:oci/nginx@1.27", ""},
		{"namespace kept, name dropped", "pkg:docker/library/nginx@1.27", "library"},
		{
			"repository_url qualifier, trailing name segment dropped",
			"pkg:oci/nginx@1.27?repository_url=docker.io/library/nginx",
			"docker.io/library",
		},
		{
			"repository_url with no trailing name segment is left alone",
			"pkg:oci/nginx@1.27?repository_url=docker.io/mynginx",
			"docker.io/mynginx",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Location(tt.purl)
			if err != nil {
				t.Fatalf("Location(%q) error = %v", tt.purl, err)
			}
			if got != tt.want {
				t.Errorf("Location(%q) = %q, want %q", tt.purl, got, tt.want)
			}
		})
	}
}

func TestLocationInvalidPurl(t *testing.T) {
	if _, err := Location("not-a-purl"); err == nil {
		t.Fatal("Location() with an unparseable purl: expected error, got nil")
	}
}
