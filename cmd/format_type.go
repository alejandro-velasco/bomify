package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/spf13/cobra"
)

// formatType is a --format value: how a command prints its result. It
// implements pflag.Value, so the flag refuses any other.
type formatType string

const (
	formatTypeJSON formatType = "json"
	formatTypeText formatType = "text"
)

// defaultFormatType is --format's default.
const defaultFormatType = formatTypeText

func (f *formatType) String() string {
	return string(*f)
}

// Set sets f to val, in any case, refusing a format it isn't.
func (f *formatType) Set(val string) error {
	format := formatType(strings.ToLower(val))
	if format != formatTypeJSON && format != formatTypeText {
		return fmt.Errorf("must be %s or %s", formatTypeJSON, formatTypeText)
	}
	*f = format
	return nil
}

// Type is the flag's value placeholder in help: "--format format".
func (f *formatType) Type() string {
	return "format"
}

// formatUsage is --format's help.
const formatUsage = "print the result as text or json"

// registerFormat registers --format (-F) on cmd, setting format, text by
// default, so every command's is the same.
func registerFormat(cmd *cobra.Command, format *formatType) {
	*format = defaultFormatType
	cmd.Flags().VarP(format, "format", "F", formatUsage)
}

// writeJSON prints v as --format json prints a result: indented, as
// fsutil.WriteJSON writes a file.
func writeJSON(w io.Writer, v any) error {
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(v)
}
