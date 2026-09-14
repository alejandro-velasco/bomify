package chart

import "testing"

func TestResolveClassicRepository(t *testing.T) {
	ref, err := Resolve("pkg:helm/nginx@1.2.3?repository_url=https://charts.example.com")
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}

	if ref.Name != "nginx" || ref.Version != "1.2.3" || ref.RepositoryURL != "https://charts.example.com" {
		t.Errorf("Resolve() = %+v, want Name=nginx Version=1.2.3 RepositoryURL=https://charts.example.com", ref)
	}
	if ref.OCI {
		t.Error("OCI = true for a classic https:// repository_url, want false")
	}
}

func TestResolveOCIRepository(t *testing.T) {
	ref, err := Resolve("pkg:helm/nginx@1.2.3?repository_url=oci://registry.example.com/charts")
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}

	if !ref.OCI {
		t.Error("OCI = false for an oci:// repository_url, want true")
	}
}

func TestResolveMissingRepositoryURL(t *testing.T) {
	if _, err := Resolve("pkg:helm/nginx@1.2.3"); err == nil {
		t.Fatal("Resolve() with no repository_url qualifier: expected error, got nil")
	}
}

func TestResolveMissingVersion(t *testing.T) {
	if _, err := Resolve("pkg:helm/nginx?repository_url=https://charts.example.com"); err == nil {
		t.Fatal("Resolve() with no version: expected error, got nil")
	}
}

func TestResolveInvalidPurl(t *testing.T) {
	if _, err := Resolve("not-a-purl"); err == nil {
		t.Fatal("Resolve() with an unparseable purl: expected error, got nil")
	}
}

func TestFilename(t *testing.T) {
	ref := Ref{Name: "nginx", Version: "1.2.3"}
	if got, want := ref.Filename(), "nginx-1.2.3.tgz"; got != want {
		t.Errorf("Filename() = %q, want %q", got, want)
	}
}
