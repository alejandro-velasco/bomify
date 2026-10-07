package layout

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/alejandro-velasco/bomify/internal/fsutil"
)

func TestMigrationsReachCurrentVersion(t *testing.T) {
	if len(migrations) != CurrentVersion-1 {
		t.Fatalf("%d migrations for version %d, want %d", len(migrations), CurrentVersion, CurrentVersion-1)
	}
}

func TestCheckVersionStartsMissingDirectory(t *testing.T) {
	dataDir := filepath.Join(t.TempDir(), "data")

	if err := CheckVersion(dataDir); err != nil {
		t.Fatalf("CheckVersion: %v", err)
	}
	requireVersion(t, dataDir, CurrentVersion)
}

func TestCheckVersionStartsEmptyDirectory(t *testing.T) {
	dataDir := t.TempDir()

	if err := CheckVersion(dataDir); err != nil {
		t.Fatalf("CheckVersion: %v", err)
	}
	requireVersion(t, dataDir, CurrentVersion)

	// Checking again finds the version just written.
	if err := CheckVersion(dataDir); err != nil {
		t.Fatalf("CheckVersion again: %v", err)
	}
}

func TestCheckVersionRefusesUnversionedDirectory(t *testing.T) {
	dataDir := t.TempDir()
	if err := os.MkdirAll(Plugins(dataDir), 0o755); err != nil {
		t.Fatal(err)
	}

	err := CheckVersion(dataDir)
	if err == nil || !strings.Contains(err.Error(), "pre-alpha") {
		t.Fatalf("CheckVersion = %v, want the pre-alpha directory refused", err)
	}
	if _, err := os.Stat(VersionFile(dataDir)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("version file written for a refused directory: %v", err)
	}
}

func TestCheckVersionRefusesNewerVersion(t *testing.T) {
	dataDir := t.TempDir()
	writeTestVersion(t, dataDir, CurrentVersion+1)

	err := CheckVersion(dataDir)
	if err == nil || !strings.Contains(err.Error(), "upgrade bomify") {
		t.Fatalf("CheckVersion = %v, want the newer version refused", err)
	}
	requireVersion(t, dataDir, CurrentVersion+1)
}

func TestCheckVersionRefusesInvalidVersion(t *testing.T) {
	dataDir := t.TempDir()
	writeTestVersion(t, dataDir, -1)

	if err := CheckVersion(dataDir); err == nil {
		t.Fatal("CheckVersion succeeded on a negative version")
	}
}

func TestCheckVersionMigratesInOrder(t *testing.T) {
	dataDir := t.TempDir()
	writeTestVersion(t, dataDir, 1)

	var ran []int
	steps := []migration{
		func(string) error { ran = append(ran, 1); return nil },
		func(string) error { ran = append(ran, 2); return nil },
	}
	if err := checkVersion(dataDir, 3, steps); err != nil {
		t.Fatalf("checkVersion: %v", err)
	}
	if len(ran) != 2 || ran[0] != 1 || ran[1] != 2 {
		t.Errorf("ran migrations %v, want [1 2]", ran)
	}
	requireVersion(t, dataDir, 3)
}

func TestCheckVersionResumesAfterFailedMigration(t *testing.T) {
	dataDir := t.TempDir()
	writeTestVersion(t, dataDir, 1)

	failing := []migration{
		func(string) error { return nil },
		func(string) error { return errors.New("disk full") },
	}
	err := checkVersion(dataDir, 3, failing)
	if err == nil || !strings.Contains(err.Error(), "from version 2 to 3") {
		t.Fatalf("checkVersion = %v, want the second migration's failure", err)
	}
	// The first step is recorded, so it doesn't run again.
	requireVersion(t, dataDir, 2)

	var ran []int
	succeeding := []migration{
		func(string) error { ran = append(ran, 1); return nil },
		func(string) error { ran = append(ran, 2); return nil },
	}
	if err := checkVersion(dataDir, 3, succeeding); err != nil {
		t.Fatalf("checkVersion after fixing: %v", err)
	}
	if len(ran) != 1 || ran[0] != 2 {
		t.Errorf("ran migrations %v, want only [2]", ran)
	}
	requireVersion(t, dataDir, 3)
}

func writeTestVersion(t *testing.T, dataDir string, version int) {
	t.Helper()
	if err := writeVersion(VersionFile(dataDir), version); err != nil {
		t.Fatal(err)
	}
}

func requireVersion(t *testing.T, dataDir string, want int) {
	t.Helper()
	var recorded versionFile
	if err := fsutil.ReadJSON(VersionFile(dataDir), &recorded); err != nil {
		t.Fatal(err)
	}
	if recorded.Version != want {
		t.Errorf("version = %d, want %d", recorded.Version, want)
	}
}
