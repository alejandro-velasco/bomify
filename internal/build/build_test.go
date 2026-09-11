package build

import (
	"testing"
)

func TestRemoveTagRemovesOnlyThatTag(t *testing.T) {
	baseDir := t.TempDir()

	if err := UpdateRepositories(baseDir, []string{"myapp:v1.0", "myapp:latest"}, "abc123"); err != nil {
		t.Fatalf("UpdateRepositories: %v", err)
	}

	if err := RemoveTag(baseDir, "myapp:v1.0"); err != nil {
		t.Fatalf("RemoveTag() error = %v", err)
	}

	repos, err := ReadRepositories(baseDir)
	if err != nil {
		t.Fatalf("ReadRepositories: %v", err)
	}

	if _, ok := repos["myapp"]["v1.0"]; ok {
		t.Error("myapp:v1.0 still present after RemoveTag")
	}
	if got, ok := repos["myapp"]["latest"]; !ok || got != "abc123" {
		t.Errorf("myapp:latest = (%q, %v), want (\"abc123\", true)", got, ok)
	}
}

func TestRemoveTagDropsEmptyRepoEntry(t *testing.T) {
	baseDir := t.TempDir()

	if err := UpdateRepositories(baseDir, []string{"myapp:v1.0"}, "abc123"); err != nil {
		t.Fatalf("UpdateRepositories: %v", err)
	}

	if err := RemoveTag(baseDir, "myapp:v1.0"); err != nil {
		t.Fatalf("RemoveTag() error = %v", err)
	}

	repos, err := ReadRepositories(baseDir)
	if err != nil {
		t.Fatalf("ReadRepositories: %v", err)
	}

	if _, ok := repos["myapp"]; ok {
		t.Errorf("empty \"myapp\" repo entry left behind: %+v", repos)
	}
}

func TestRemoveTagErrorsForUnknownTag(t *testing.T) {
	baseDir := t.TempDir()

	if err := RemoveTag(baseDir, "myapp:v1.0"); err == nil {
		t.Fatal("RemoveTag() error = nil, want error for a tag that was never set")
	}

	if err := UpdateRepositories(baseDir, []string{"myapp:v1.0"}, "abc123"); err != nil {
		t.Fatalf("UpdateRepositories: %v", err)
	}
	if err := RemoveTag(baseDir, "myapp:v2.0"); err == nil {
		t.Fatal("RemoveTag() error = nil, want error for an unset version under an existing repo")
	}
}
