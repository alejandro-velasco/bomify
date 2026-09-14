package artifact

import "testing"

func TestResolve(t *testing.T) {
	ref, err := Resolve("pkg:generic/left-pad@1.3.0?download_url=https://example.com/left-pad-1.3.0.tar.gz")
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}

	if ref.Name != "left-pad" || ref.Version != "1.3.0" || ref.DownloadURL != "https://example.com/left-pad-1.3.0.tar.gz" {
		t.Errorf("Resolve() = %+v, want Name=left-pad Version=1.3.0 DownloadURL=https://example.com/left-pad-1.3.0.tar.gz", ref)
	}
}

func TestResolveMissingDownloadURL(t *testing.T) {
	if _, err := Resolve("pkg:generic/left-pad@1.3.0"); err == nil {
		t.Fatal("Resolve() with no download_url qualifier: expected error, got nil")
	}
}

func TestResolveInvalidPurl(t *testing.T) {
	if _, err := Resolve("not-a-purl"); err == nil {
		t.Fatal("Resolve() with an unparseable purl: expected error, got nil")
	}
}

func TestFilename(t *testing.T) {
	tests := []struct {
		name string
		ref  Ref
		want string
	}{
		{
			"download URL has a path basename",
			Ref{Name: "left-pad", Version: "1.3.0", DownloadURL: "https://example.com/dist/left-pad-1.3.0.tar.gz"},
			"left-pad-1.3.0.tar.gz",
		},
		{
			"download URL has a query string but the same basename",
			Ref{Name: "left-pad", Version: "1.3.0", DownloadURL: "https://example.com/dist/left-pad-1.3.0.tar.gz?token=abc"},
			"left-pad-1.3.0.tar.gz",
		},
		{
			"download URL has no path",
			Ref{Name: "left-pad", Version: "1.3.0", DownloadURL: "https://example.com"},
			"left-pad-1.3.0",
		},
		{
			"download URL has a trailing-slash-only path",
			Ref{Name: "left-pad", Version: "1.3.0", DownloadURL: "https://example.com/"},
			"left-pad-1.3.0",
		},
		{
			"no version",
			Ref{Name: "left-pad", DownloadURL: "https://example.com"},
			"left-pad",
		},
		{
			"unparseable download URL falls back to name-version",
			Ref{Name: "left-pad", Version: "1.3.0", DownloadURL: "://not a url"},
			"left-pad-1.3.0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.ref.Filename(); got != tt.want {
				t.Errorf("Filename() = %q, want %q", got, tt.want)
			}
		})
	}
}
