package plugin

import (
	"encoding/json"

	pluginlib "github.com/alejandro-velasco/bomify/pkg/plugin"
)

// Tracker shows plugin pulls as they run, with the progress each plugin
// reports to its --progress file (see
// plugins/contracts/component/v1/CONTRACT.md), which may be none.
type Tracker interface {
	// Start shows a pull of label beginning, and returns what shows the
	// rest of it.
	Start(label string) Pulling
}

// Pulling shows one pull a Tracker started.
type Pulling interface {
	// Update shows an event the plugin reported.
	Update(event pluginlib.ProgressEvent)
	// Done ends the pull, which succeeded if ok.
	Done(ok bool)
}

// showProgress shows line, from a --progress file, through pulling.
// Progress is only shown, so a line that isn't an event is skipped rather
// than failing the pull.
func showProgress(pulling Pulling, line []byte) {
	var event pluginlib.ProgressEvent
	if err := json.Unmarshal(line, &event); err != nil || event.Name == "" {
		return
	}
	pulling.Update(event)
}
