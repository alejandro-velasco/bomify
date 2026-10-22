package plugin

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// readProgress is the events in the progress file at path.
func readProgress(t *testing.T, path string) []ProgressEvent {
	t.Helper()
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()

	var events []ProgressEvent
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		var event ProgressEvent
		if err := json.Unmarshal(scanner.Bytes(), &event); err != nil {
			t.Fatalf("line %q: %v", scanner.Text(), err)
		}
		events = append(events, event)
	}
	return events
}

func TestProgressWriterReportsAtStartAtMostEveryIntervalAndOnClose(t *testing.T) {
	path := filepath.Join(t.TempDir(), "progress")
	progress, closeProgress, err := OpenProgress(path)
	if err != nil {
		t.Fatal(err)
	}
	defer closeProgress()

	writer := progress.Writer("layer", 0)
	for range 3 {
		writer.Write([]byte("ab"))
	}
	time.Sleep(progressInterval)
	writer.Write([]byte("c"))
	writer.Close()

	got := readProgress(t, path)
	want := []ProgressEvent{
		{Name: "layer", Current: 0},
		{Name: "layer", Current: 7},
		{Name: "layer", Current: 7},
	}
	if len(got) != len(want) {
		t.Fatalf("events = %+v, want %+v", got, want)
	}
	for index := range want {
		if got[index] != want[index] {
			t.Errorf("event %d = %+v, want %+v", index, got[index], want[index])
		}
	}
}

func TestNilProgressReportsNothing(t *testing.T) {
	progress, closeProgress, err := OpenProgress("")
	if err != nil {
		t.Fatal(err)
	}
	defer closeProgress()
	if progress != nil {
		t.Fatalf("OpenProgress(\"\") = %v, want nil", progress)
	}

	writer := progress.Writer("part", 1)
	if _, err := writer.Write([]byte("x")); err != nil {
		t.Errorf("Write: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
	progress.Report("part", 1, 1)
}
