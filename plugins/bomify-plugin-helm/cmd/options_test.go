package cmd

import (
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"
)

func TestGenerateRequiresChartAndRepo(t *testing.T) {
	logger := slog.New(slog.DiscardHandler)
	for config, want := range map[string]string{
		`{}`:              `"chart"`,
		`{"chart":"web"}`: `"repo"`,
	} {
		if _, err := (sbomGenerator{}).Generate(context.Background(), json.RawMessage(config), logger); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("Generate(%s) = %v, want an error naming %s", config, err, want)
		}
	}
}
