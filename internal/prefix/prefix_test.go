package prefix

import "testing"

func TestMatches(t *testing.T) {
	tests := []struct {
		address, match string
		want           bool
	}{
		{"docker.io/org/repo", "docker.io/org", true},
		{"docker.io/org/repo", "docker.io/org/repo", true},
		{"docker.io/organization", "docker.io/org", false},
		{"docker.io/org", "docker.io/org/repo", false},
		{"oci://docker.io/org/repo/", "docker.io/org", true},
		{"docker.io/org/repo", "https://docker.io/org/", true},
		{"anything", "", true},
		{"", "", true},
		{"", "docker.io", false},
	}
	for _, tt := range tests {
		if got := Matches(tt.address, tt.match); got != tt.want {
			t.Errorf("Matches(%q, %q) = %v, want %v", tt.address, tt.match, got, tt.want)
		}
	}
}

func TestSegments(t *testing.T) {
	tests := map[string]int{"": 0, "/": 0, "docker.io": 1, "docker.io/org/": 2, "oci://docker.io/org/repo": 3}
	for match, want := range tests {
		if got := Segments(match); got != want {
			t.Errorf("Segments(%q) = %d, want %d", match, got, want)
		}
	}
}
