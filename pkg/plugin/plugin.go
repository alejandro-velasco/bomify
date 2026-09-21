// Package plugin is the Go library for implementing a bomify-plugin-<kind>
// binary: the Result/Hash/RemoteResult types the subprocess contract's
// JSON output mirrors, their Print methods to emit it correctly, and (in
// log.go) OpenLog for the plugin's own --log file. See plugins/CONTRACT.md
// for the full contract this package implements one side of; unlike that
// document, this package is importable from outside this module, so a
// third-party plugin (in its own separate Go module) can depend on it
// directly.
package plugin

import (
	"encoding/json"
	"fmt"
	"io"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

// Result is the structured output a plugin prints to stdout on success.
type Result struct {
	// OutputPath is the location of the artifact the plugin produced.
	OutputPath string `json:"outputPath"`
	// Message is an optional human-readable summary of what happened.
	Message string `json:"message,omitempty"`
	// Hash is the content hash of the pulled artifact, for the algorithm
	// requested via --hash. A pull plugin should leave this zero if it
	// cannot compute a hash for the requested algorithm.
	Hash Hash `json:"hash,omitempty"`
}

// Hash is a content hash reported by a plugin, mirroring cdx.Hash.
type Hash struct {
	Algorithm cdx.HashAlgorithm `json:"algorithm,omitempty"`
	Value     string            `json:"value,omitempty"`
}

// Print writes r to w as the single JSON object bomify expects a plugin to
// print to stdout on success. Plugins should call this instead of
// re-implementing JSON encoding themselves.
func (r *Result) Print(w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(r); err != nil {
		return fmt.Errorf("encode result: %w", err)
	}
	return nil
}

// RemoteResult is the structured output a plugin prints to stdout on
// success for its "remote" subcommand.
type RemoteResult struct {
	// Remote identifies where a component's content comes from or is
	// published under — a registry/namespace address, a source URL, etc.
	// It must be in the same shape push's own --remote expects to
	// receive: without the component's own trailing name if push appends
	// that itself, or the exact complete destination if push doesn't
	// append anything at all — see plugins/CONTRACT.md's RemoteResult
	// section for why. A distribution rule matched by --match can
	// substitute part of this value back into --remote for a later push,
	// preserving whatever came after the matched prefix.
	Remote string `json:"remote"`
}

// Print writes r to w as the single JSON object bomify expects a plugin's
// "remote" subcommand to print to stdout on success.
func (r *RemoteResult) Print(w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(r); err != nil {
		return fmt.Errorf("encode remote result: %w", err)
	}
	return nil
}
