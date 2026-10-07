package hub

import (
	"strings"
	"testing"
)

const testCommit = "71034c5d8bde858ff824298bdedc65515b97d2b9"

func TestResolve(t *testing.T) {
	ref, err := Resolve("pkg:huggingface/microsoft/deberta-v3-base@559062AD13D311B87B2C455E67DCD5F1C8F65111?repository_url=https://hub.example.com/")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	want := Ref{
		Namespace: "microsoft",
		Name:      "deberta-v3-base",
		Revision:  "559062ad13d311b87b2c455e67dcd5f1c8f65111",
		Endpoint:  "https://hub.example.com",
	}
	if ref != want {
		t.Errorf("Resolve = %+v, want %+v", ref, want)
	}
	if got := ref.RepoID(); got != "microsoft/deberta-v3-base" {
		t.Errorf("RepoID = %q", got)
	}
}

func TestResolveRejects(t *testing.T) {
	for _, tc := range []struct {
		purl string
		want string
	}{
		{"pkg:generic/model@" + testCommit, "isn't a huggingface purl"},
		{"pkg:huggingface/model@" + testCommit, "isn't pkg:huggingface/<namespace>/<name>@<commit>"},
		{"pkg:huggingface/org/model", "isn't pinned to a commit"},
		{"pkg:huggingface/org/model@main", "isn't pinned to a commit"},
		{"pkg:huggingface/org/model@71034c5", "isn't pinned to a commit"},
		{"pkg:huggingface/org/model@" + testCommit + "#model.safetensors", "has a subpath"},
		{"pkg:huggingface/org/model@" + testCommit + "?repository_url=http://hub.example.com", "isn't an https:// hub address"},
	} {
		if _, err := Resolve(tc.purl); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("Resolve(%q) = %v, want an error containing %q", tc.purl, err, tc.want)
		}
	}
}

func TestRemote(t *testing.T) {
	for _, tc := range []struct {
		purl string
		want string
	}{
		{"pkg:huggingface/meta-llama/Llama-3.1-8B@" + testCommit, "huggingface.co/meta-llama"},
		{"pkg:huggingface/org/model@" + testCommit + "?repository_url=https://hub.example.com/mirror", "hub.example.com/mirror/org"},
	} {
		ref, err := Resolve(tc.purl)
		if err != nil {
			t.Fatalf("Resolve(%q): %v", tc.purl, err)
		}
		if got := ref.Remote(); got != tc.want {
			t.Errorf("Remote(%q) = %q, want %q", tc.purl, got, tc.want)
		}
	}
}

func TestParseRemote(t *testing.T) {
	for _, tc := range []struct {
		remote, endpoint, namespace string
	}{
		{"huggingface.co/my-org", "https://huggingface.co", "my-org"},
		{"https://hub.example.com/mirror/my-org/", "https://hub.example.com/mirror", "my-org"},
	} {
		endpoint, namespace, err := ParseRemote(tc.remote)
		if err != nil || endpoint != tc.endpoint || namespace != tc.namespace {
			t.Errorf("ParseRemote(%q) = %q, %q, %v; want %q, %q", tc.remote, endpoint, namespace, err, tc.endpoint, tc.namespace)
		}
	}

	for _, remote := range []string{"my-org", "huggingface.co/", "/my-org", "http://huggingface.co/my-org"} {
		if _, _, err := ParseRemote(remote); err == nil {
			t.Errorf("ParseRemote(%q) succeeded", remote)
		}
	}
}

// TestRemoteRoundTrips covers what bomify distribute relies on: what
// Remote reports, push accepts as --remote, naming the same hub and
// namespace.
func TestRemoteRoundTrips(t *testing.T) {
	ref, err := Resolve("pkg:huggingface/org/model@" + testCommit + "?repository_url=https://hub.example.com")
	if err != nil {
		t.Fatal(err)
	}
	endpoint, namespace, err := ParseRemote(ref.Remote())
	if err != nil || endpoint != ref.Endpoint || namespace != ref.Namespace {
		t.Errorf("ParseRemote(Remote()) = %q, %q, %v; want %q, %q", endpoint, namespace, err, ref.Endpoint, ref.Namespace)
	}
}
